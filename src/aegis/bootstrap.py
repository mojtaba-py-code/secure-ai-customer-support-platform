"""Composition root: turns :class:`Settings` into wired, long-lived components.

Everything with a lifecycle (engine, Redis, Qdrant, HTTP clients, the model client) is created
here once per process and closed in :meth:`AppContainer.close`. Request-scoped objects (services
bound to one database session) are built by :class:`RequestServices`.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from functools import cached_property
from urllib.parse import urlsplit

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from aegis.agents.classifier import IntentClassifier
from aegis.agents.guard import OutputGuard
from aegis.agents.intents import IntentRegistry
from aegis.agents.memory import ConversationMemory, ConversationStateStore
from aegis.agents.offline import OfflineSupportModel
from aegis.agents.orchestrator import AgentSettings, SupportAgent
from aegis.agents.policy import PolicySettings, TurnPolicy
from aegis.agents.prompts import build_agent_system_prompt
from aegis.agents.rules import RuleBasedClassifier
from aegis.core.config import (
    EmailBackend,
    EmbeddingProviderName,
    LLMProviderName,
    PaymentProviderName,
    Settings,
)
from aegis.core.egress import EgressPolicy, build_http_client
from aegis.core.resilience import CircuitBreaker
from aegis.db.session import create_engine, create_sessionmaker
from aegis.kv.base import KeyBuilder, KeyValueStore
from aegis.kv.memory import MemoryKeyValueStore
from aegis.kv.rate_limit import RateLimiter, RateLimitPolicy
from aegis.kv.redis_store import RedisKeyValueStore
from aegis.llm.base import LLMProvider
from aegis.llm.gateway import BudgetGuard, LLMGateway, ModelRoutes
from aegis.observability import metrics
from aegis.rag.embeddings import Embedder, HashingEmbedder, VoyageEmbedder
from aegis.rag.retriever import KnowledgeRetriever, RetrievalSettings
from aegis.rag.vector_store import QdrantVectorStore
from aegis.security.crypto import configure_field_cipher, derive_secret
from aegis.security.injection import PromptInjectionDetector
from aegis.security.passwords import PasswordHasher
from aegis.security.tokens import TokenService
from aegis.services.actions import PendingActionService
from aegis.services.audit import AuditService
from aegis.services.auth import AuthService
from aegis.services.commerce import CustomerService, OrderService, ProductService, RefundService
from aegis.services.conversations import ConversationService
from aegis.services.email import DevMailboxSender, DisabledEmailSender, EmailSender, SmtpEmailSender
from aegis.services.handoff import HandoffService
from aegis.services.idempotency import IdempotencyService
from aegis.services.knowledge import ChunkingSettings, KnowledgeService
from aegis.services.maintenance import MaintenanceService
from aegis.services.mfa import MfaService
from aegis.services.payments import (
    PaymentGateway,
    SimulatedPaymentGateway,
    StripePaymentGateway,
)
from aegis.services.privacy import PrivacyService
from aegis.services.tickets import TicketService
from aegis.services.usage import UsageService
from aegis.services.users import UserAdminService
from aegis.tools.catalog import TOOLS
from aegis.tools.executor import ToolExecutor
from aegis.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class RateLimitPolicies:
    login_ip: RateLimitPolicy
    login_account: RateLimitPolicy
    password_reset: RateLimitPolicy
    refresh: RateLimitPolicy
    api_user: RateLimitPolicy
    api_ip: RateLimitPolicy
    llm_minute: RateLimitPolicy
    llm_day: RateLimitPolicy
    upload: RateLimitPolicy
    admin: RateLimitPolicy
    privacy_export: RateLimitPolicy

    @classmethod
    def from_settings(cls, s: Settings) -> RateLimitPolicies:
        return cls(
            login_ip=RateLimitPolicy("login_ip", s.rl_login_per_ip_per_minute, 60),
            login_account=RateLimitPolicy(
                "login_account", s.rl_login_per_account_per_15_minutes, 900
            ),
            password_reset=RateLimitPolicy("password_reset", s.rl_password_reset_per_hour, 3_600),
            refresh=RateLimitPolicy("refresh", s.rl_refresh_per_minute, 60),
            api_user=RateLimitPolicy("api_user", s.rl_api_per_user_per_minute, 60),
            api_ip=RateLimitPolicy("api_ip", s.rl_api_per_ip_per_minute, 60),
            llm_minute=RateLimitPolicy("llm_minute", s.rl_llm_per_user_per_minute, 60),
            llm_day=RateLimitPolicy("llm_day", s.rl_llm_per_user_per_day, 86_400),
            upload=RateLimitPolicy("upload", s.rl_upload_per_hour, 3_600),
            admin=RateLimitPolicy("admin", s.rl_admin_per_minute, 60),
            privacy_export=RateLimitPolicy("privacy_export", s.rl_privacy_export_per_day, 86_400),
        )


class AppContainer:
    def __init__(
        self, settings: Settings, *, kv: KeyValueStore | None = None, llm: LLMProvider | None = None
    ) -> None:
        self.settings = settings
        #: Wall clock for time-based one-time passwords (replaceable in tests).
        self.epoch_seconds: Callable[[], float] = time.time
        configure_field_cipher(settings.encryption_keys)
        self.engine: AsyncEngine = create_engine(settings)
        self.sessionmaker: async_sessionmaker[AsyncSession] = create_sessionmaker(self.engine)
        self.keys = KeyBuilder(settings.redis_key_prefix, settings.env.value)
        self.kv: KeyValueStore = kv or self._build_kv()
        self.rate_limiter = RateLimiter(
            self.kv, self.keys, on_degraded=lambda: metrics.security_event("rate_limit_degraded")
        )
        self.rate_limits = RateLimitPolicies.from_settings(settings)
        self.hasher = PasswordHasher(
            time_cost=settings.argon2_time_cost,
            memory_cost_kib=settings.argon2_memory_cost_kib,
            parallelism=settings.argon2_parallelism,
        )
        self.tokens = TokenService(
            secret=settings.jwt_secret.get_secret_value(),
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            access_ttl_seconds=settings.access_token_ttl_seconds,
        )
        self.detector = PromptInjectionDetector()
        self.audit = AuditService(self.sessionmaker)
        self.usage = UsageService(self.sessionmaker)
        self.email: EmailSender = self._build_email()
        self.payments: PaymentGateway = self._build_payments()
        self.embedder: Embedder = self._build_embedder()
        self.vector_store = QdrantVectorStore.create(
            url=settings.qdrant_url,
            api_key=settings.qdrant_api_key.get_secret_value() if settings.qdrant_api_key else None,
            location=settings.qdrant_location,
            collection=settings.qdrant_collection,
            dimensions=self.embedder.dimensions,
        )
        self.retriever = KnowledgeRetriever(
            store=self.vector_store,
            embedder=self.embedder,
            detector=self.detector,
            settings=RetrievalSettings(
                top_k=settings.rag_top_k,
                candidate_k=settings.rag_candidate_k,
                score_threshold=settings.rag_score_threshold,
                max_context_chars=settings.rag_max_context_chars,
                max_chunks_per_document=settings.rag_max_chunks_per_document,
            ),
            cache=self.kv,
            cache_keys=self.keys,
        )
        self.tool_registry = ToolRegistry(TOOLS)
        self.intents = IntentRegistry.load_default(known_tools=self.tool_registry.names)
        self.rules = RuleBasedClassifier(self.intents)
        self.offline_model = OfflineSupportModel(self.intents, self.rules)
        self.llm = self._build_gateway(llm)
        canary = (
            "AEGIS-"
            + derive_secret(settings.jwt_secret.get_secret_value(), "prompt-canary", 20).upper()
        )
        self.system_prompt = build_agent_system_prompt(
            company=settings.company_name, help_center_url=settings.help_center_url, canary=canary
        )
        self.agent = SupportAgent(
            gateway=self.llm,
            classifier=IntentClassifier(
                gateway=self.llm,
                registry=self.intents,
                rules=self.rules,
                max_output_tokens=settings.llm_classifier_max_tokens,
            ),
            policy=TurnPolicy(
                self.tool_registry,
                PolicySettings(
                    min_confidence=settings.agent_min_confidence,
                    suspicious_threshold=settings.agent_suspicious_escalation_threshold,
                    failure_threshold=settings.agent_failure_escalation_threshold,
                ),
            ),
            retriever=self.retriever,
            tools=self.tool_registry,
            executor=ToolExecutor(
                self.tool_registry,
                audit=self.audit,
                timeout_seconds=settings.agent_tool_timeout_seconds,
                max_calls_per_turn=settings.agent_max_tool_calls,
            ),
            guard=OutputGuard(
                canary=canary,
                system_prompt=self.system_prompt,
                allowed_link_domains=settings.agent_allowed_link_domains,
                max_chars=settings.agent_max_response_chars,
            ),
            memory=ConversationMemory(
                gateway=self.llm,
                history_messages=settings.agent_history_messages,
                summary_trigger=settings.agent_summary_trigger_messages,
                summary_max_tokens=settings.llm_summary_max_tokens,
            ),
            state_store=ConversationStateStore(self.kv, self.keys),
            detector=self.detector,
            audit=self.audit,
            kv=self.kv,
            keys=self.keys,
            system_prompt=self.system_prompt,
            settings=AgentSettings(
                max_iterations=settings.agent_max_iterations,
                turn_timeout_seconds=settings.agent_turn_timeout_seconds,
                max_message_chars=settings.agent_max_message_chars,
                agent_max_tokens=settings.llm_agent_max_tokens,
                failure_threshold=settings.agent_failure_escalation_threshold,
            ),
        )

    # --- builders ------------------------------------------------------------------------------------
    def _build_kv(self) -> KeyValueStore:
        if self.settings.redis_url is not None:
            return RedisKeyValueStore.from_url(
                self.settings.redis_url.get_secret_value(),
                socket_timeout=self.settings.redis_socket_timeout_seconds,
            )
        logger.warning(
            "no AEGIS_REDIS_URL: using the in-process key-value store (development only)"
        )
        return MemoryKeyValueStore()

    def _build_email(self) -> EmailSender:
        s = self.settings
        if s.email_backend is EmailBackend.SMTP and s.smtp_host:
            return SmtpEmailSender(
                host=s.smtp_host,
                port=s.smtp_port,
                username=s.smtp_username,
                password=s.smtp_password.get_secret_value() if s.smtp_password else None,
                sender=s.email_from,
                timeout_seconds=s.smtp_timeout_seconds,
            )
        if s.email_backend is EmailBackend.DEV_MAILBOX:
            return DevMailboxSender(s.mailbox_dir, s.email_from)
        return DisabledEmailSender()

    def _build_payments(self) -> PaymentGateway:
        s = self.settings
        if s.payment_provider is PaymentProviderName.STRIPE and s.stripe_api_key is not None:
            return StripePaymentGateway(
                api_key=s.stripe_api_key.get_secret_value(),
                base_url=s.stripe_base_url,
                client=build_http_client(timeout_seconds=15.0),
                policy=EgressPolicy([urlsplit(s.stripe_base_url).hostname or ""]),
            )
        return SimulatedPaymentGateway()

    def _build_embedder(self) -> Embedder:
        s = self.settings
        if s.embedding_provider is EmbeddingProviderName.VOYAGE and s.voyage_api_key is not None:
            host = urlsplit(s.voyage_base_url).hostname or ""
            return VoyageEmbedder(
                api_key=s.voyage_api_key.get_secret_value(),
                model=s.voyage_model,
                base_url=s.voyage_base_url,
                dimensions=s.embedding_dimensions,
                client=build_http_client(timeout_seconds=20.0),
                policy=EgressPolicy([host]),
            )
        return HashingEmbedder(s.embedding_dimensions)

    def _build_gateway(self, override: LLMProvider | None) -> LLMGateway:
        s = self.settings
        primary: LLMProvider
        if override is not None:
            primary = override
        elif s.llm_provider is LLMProviderName.ANTHROPIC and s.anthropic_api_key is not None:
            # Imported lazily: the SDK is large and the offline mode does not need it.
            from aegis.llm.anthropic_provider import AnthropicProvider  # noqa: PLC0415

            primary = AnthropicProvider(
                api_key=s.anthropic_api_key.get_secret_value(),
                base_url=s.anthropic_base_url,
                timeout_seconds=s.llm_request_timeout_seconds,
                max_retries=s.llm_max_retries,
                agent_effort=s.llm_agent_effort,
                refusal_fallback=s.llm_refusal_fallback_enabled,
                prompt_caching=s.llm_prompt_caching,
            )
        else:
            primary = self.offline_model
        fallback = (
            self.offline_model
            if s.llm_fallback_to_offline and primary is not self.offline_model
            else None
        )
        return LLMGateway(
            primary=primary,
            fallback=fallback,
            routes=ModelRoutes(
                agent=s.llm_agent_model,
                classify=s.llm_classifier_model,
                summarize=s.llm_summary_model,
            ),
            budget=BudgetGuard(
                self.kv,
                self.keys,
                user_daily_tokens=s.llm_user_daily_token_budget,
                global_daily_cost_usd=s.llm_global_daily_cost_limit_usd,
            ),
            breaker=CircuitBreaker(
                "llm",
                failure_threshold=s.llm_circuit_failure_threshold,
                reset_timeout=s.llm_circuit_reset_seconds,
            ),
            call_timeout_seconds=s.llm_request_timeout_seconds + 5,
            usage_sink=self.usage,
        )

    # --- lifecycle -------------------------------------------------------------------------------------
    async def startup(self) -> None:
        await self.vector_store.ensure_collection()
        if not self.settings.qdrant_url:
            # Embedded vector index (development): rebuild it from the database if it is empty.
            async with self.sessionmaker() as session:
                rebuilt = await RequestServices(self, session).knowledge.reconcile_index()
            if rebuilt:
                logger.info(
                    "rebuilt local vector index",
                    extra={"event": "kb.reconciled", "documents": rebuilt},
                )

    async def close(self) -> None:
        await self.llm.close()
        await self.embedder.close()
        await self.payments.close()
        await self.vector_store.close()
        await self.kv.close()
        await self.engine.dispose()


class RequestServices:
    """Services bound to one database session (one request or one worker iteration)."""

    def __init__(self, container: AppContainer, session: AsyncSession) -> None:
        self._c = container
        self.session = session

    @cached_property
    def mfa(self) -> MfaService:
        c = self._c
        return MfaService(
            self.session,
            settings=c.settings,
            hasher=c.hasher,
            audit=c.audit,
            epoch_seconds=c.epoch_seconds,
        )

    @cached_property
    def auth(self) -> AuthService:
        c = self._c
        return AuthService(
            self.session,
            settings=c.settings,
            hasher=c.hasher,
            tokens=c.tokens,
            audit=c.audit,
            mfa=self.mfa,
        )

    @cached_property
    def users(self) -> UserAdminService:
        c = self._c
        return UserAdminService(self.session, settings=c.settings, hasher=c.hasher, audit=c.audit)

    @cached_property
    def conversations(self) -> ConversationService:
        return ConversationService(self.session, audit=self._c.audit)

    @cached_property
    def handoff(self) -> HandoffService:
        return HandoffService(self.session, audit=self._c.audit)

    @cached_property
    def orders(self) -> OrderService:
        return OrderService(self.session, audit=self._c.audit, gateway=self._c.payments)

    @cached_property
    def refunds(self) -> RefundService:
        return RefundService(self.session, audit=self._c.audit, gateway=self._c.payments)

    @cached_property
    def products(self) -> ProductService:
        return ProductService(self.session)

    @cached_property
    def customers(self) -> CustomerService:
        return CustomerService(self.session)

    @cached_property
    def tickets(self) -> TicketService:
        return TicketService(
            self.session,
            audit=self._c.audit,
            max_per_day=self._c.settings.agent_max_tickets_per_day,
        )

    @cached_property
    def actions(self) -> PendingActionService:
        return PendingActionService(
            self.session,
            orders=self.orders,
            refunds=self.refunds,
            audit=self._c.audit,
            ttl_seconds=self._c.settings.agent_action_ttl_seconds,
        )

    @cached_property
    def knowledge(self) -> KnowledgeService:
        s = self._c.settings
        return KnowledgeService(
            self.session,
            store=self._c.vector_store,
            embedder=self._c.embedder,
            detector=self._c.detector,
            chunking=ChunkingSettings(
                chunk_chars=s.rag_chunk_chars,
                overlap_chars=s.rag_chunk_overlap_chars,
                max_chunks=s.rag_max_chunks_per_upload,
            ),
            max_upload_bytes=s.max_upload_bytes,
            audit=self._c.audit,
        )

    @cached_property
    def idempotency(self) -> IdempotencyService:
        return IdempotencyService(
            self.session, ttl_seconds=self._c.settings.idempotency_ttl_seconds
        )

    @cached_property
    def privacy(self) -> PrivacyService:
        return PrivacyService(
            self.session, hasher=self._c.hasher, tickets=self.tickets, audit=self._c.audit
        )

    @cached_property
    def maintenance(self) -> MaintenanceService:
        return MaintenanceService(
            self.session,
            privacy=self.privacy,
            conversation_retention_days=self._c.settings.conversation_retention_days,
        )

    @property
    def tools(self) -> RequestServices:
        return self

    async def rollback(self) -> None:
        await self.session.rollback()
