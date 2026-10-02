"""Typed application settings, loaded from ``AEGIS_*`` environment variables (and ``.env``).

Design rules:

* Secrets are ``SecretStr`` so they never appear in ``repr()``, logs or tracebacks, and
  validation errors never echo input values (``hide_input_in_errors``).
* An empty variable (``AEGIS_METRICS_TOKEN=``) means "not set", never "set to an empty
  secret" - an empty token must not become a valid credential.
* In production, secrets can be mounted as files (Docker/Kubernetes secrets): point
  ``AEGIS_SECRETS_DIR`` at a directory containing files named after the variables
  (``AEGIS_JWT_SECRET``, ``AEGIS_DATABASE_URL``, ...). Environment variables take precedence.
* Development convenience never leaks into production: the model validator refuses to start
  a production process with SQLite, the in-process key-value store, a local vector index,
  wildcard CORS/hosts, the development mailbox or missing secrets.
* Nothing here has side effects; the composition root (:mod:`aegis.bootstrap`) turns
  settings into clients.
"""

from __future__ import annotations

import base64
import binascii
import os
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

_PLACEHOLDER_MARKERS = ("change-me", "changeme", "replace-me", "example", "placeholder")


class Environment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"


class LLMProviderName(StrEnum):
    OFFLINE = "offline"
    ANTHROPIC = "anthropic"


class EmbeddingProviderName(StrEnum):
    HASHING = "hashing"
    VOYAGE = "voyage"


class EmailBackend(StrEnum):
    DISABLED = "disabled"
    DEV_MAILBOX = "dev_mailbox"
    SMTP = "smtp"


class PaymentProviderName(StrEnum):
    SIMULATED = "simulated"
    STRIPE = "stripe"


Effort = Literal["low", "medium", "high", "xhigh", "max"]
CommaList = Annotated[list[str], NoDecode]


def _split_csv(value: object) -> object:
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return value


def _is_valid_fernet_key(key: str) -> bool:
    try:
        return len(base64.urlsafe_b64decode(key.encode("ascii"))) == 32
    except (binascii.Error, ValueError, UnicodeEncodeError):
        return False


class Settings(BaseSettings):
    """All runtime configuration. Field names map to ``AEGIS_<FIELD_NAME>`` variables."""

    model_config = SettingsConfigDict(
        env_prefix="AEGIS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        env_ignore_empty=True,
        hide_input_in_errors=True,
        validate_default=True,
        use_attribute_docstrings=True,  # the docstring under each field documents it
    )

    # --- application -------------------------------------------------------------------
    env: Environment = Environment.DEVELOPMENT
    """Deployment environment; `production` enforces the safety rules listed above."""
    app_name: str = "AegisSupport AI"
    """Application name shown in the OpenAPI document."""
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    """Minimum log level (`DEBUG` is refused in production)."""
    log_json: bool = True
    """One JSON object per log line (for log shippers; required in production); `false` prints readable lines."""
    api_docs_enabled: bool | None = None
    """Serve `/docs` and `/openapi.json`; unset means everywhere except production."""
    company_name: str = "Acme Home Electronics"
    """Company name used in the assistant's prompt and in e-mails."""
    help_center_url: str = "https://help.acme.example"
    """Help-centre URL the assistant is told to link to (the guard enforces the link allow-list)."""

    # --- http server -------------------------------------------------------------------
    allowed_hosts: CommaList = Field(
        default_factory=lambda: ["localhost", "127.0.0.1", "testserver"]
    )
    """Accepted `Host` header values (other hosts get 400); explicit names in production."""
    cors_origins: CommaList = Field(default_factory=list)
    """Browser origins allowed by CORS; empty disables CORS. HTTPS-only, no `*`, in production."""
    trusted_proxies: CommaList = Field(default_factory=list)
    """Proxy addresses/networks whose `X-Forwarded-For` is trusted for the client IP."""
    max_request_body_bytes: int = Field(default=65_536, ge=1_024, le=10_485_760)
    """Largest accepted request body (JSON endpoints); larger bodies get 413."""
    max_upload_bytes: int = Field(default=1_048_576, ge=1_024, le=10_485_760)
    """Largest accepted knowledge-base upload."""
    hsts_enabled: bool = False
    """Send `Strict-Transport-Security`; required in production (serve behind TLS)."""

    # --- database ------------------------------------------------------------------------
    database_url: SecretStr = SecretStr("sqlite+aiosqlite:///./var/aegis.db")
    """Async SQLAlchemy URL: `postgresql+asyncpg://` in production, SQLite for development only."""
    database_pool_size: int = Field(default=10, ge=1, le=100)
    """Connections kept open per process (PostgreSQL)."""
    database_max_overflow: int = Field(default=10, ge=0, le=100)
    """Extra connections allowed during bursts (PostgreSQL)."""
    database_pool_timeout_seconds: float = Field(default=10.0, gt=0, le=120)
    """How long a request waits for a free connection before failing."""
    database_statement_timeout_ms: int = Field(default=15_000, ge=100, le=600_000)
    """PostgreSQL `statement_timeout` for application sessions."""
    database_echo: bool = False
    """Log every SQL statement; refused in production (parameters contain customer data)."""

    # --- redis ---------------------------------------------------------------------------------
    redis_url: SecretStr | None = None
    """Redis for rate limits, locks, caches and idempotency; unset means in-process (single process only)."""
    redis_key_prefix: str = Field(default="aegis", pattern=r"^[a-z][a-z0-9_-]{1,31}$")
    """Prefix of every key; the Redis ACL in docker-compose.yml confines the app to it."""
    redis_socket_timeout_seconds: float = Field(default=2.0, gt=0, le=30)
    """Socket timeout for Redis commands."""

    # --- authentication & cryptography ----------------------------------------------------------
    jwt_secret: SecretStr
    """HMAC key for access tokens (HS256): at least 32 random characters."""
    jwt_issuer: str = "aegis-support"
    """`iss` claim written into and required from access tokens."""
    jwt_audience: str = "aegis-support-api"
    """`aud` claim written into and required from access tokens."""
    access_token_ttl_seconds: int = Field(default=900, ge=60, le=3_600)
    """Access-token lifetime."""
    refresh_token_ttl_seconds: int = Field(default=1_209_600, ge=3_600, le=7_776_000)
    """Refresh-token lifetime; refresh tokens rotate on every use."""
    session_max_age_seconds: int = Field(default=2_592_000, ge=3_600, le=15_552_000)
    """Absolute session lifetime; refreshing cannot extend a session past it."""
    field_encryption_keys: SecretStr
    """Comma-separated Fernet keys for encrypted columns; the first encrypts, the rest only decrypt."""
    password_min_length: int = Field(default=12, ge=8, le=64)
    """Minimum password length (common and account-derived passwords are refused too)."""
    login_max_failed_attempts: int = Field(default=5, ge=3, le=20)
    """Failed logins before the account is locked temporarily."""
    login_lockout_seconds: int = Field(default=900, ge=60, le=86_400)
    """Lockout duration after too many failed logins."""
    password_reset_ttl_seconds: int = Field(default=1_800, ge=300, le=86_400)
    """Lifetime of a single-use password-reset token."""
    password_reset_url: str = "https://support.acme.example/reset-password"  # noqa: S105 - a URL
    """Front-end page that receives the reset token (in the URL fragment)."""
    argon2_time_cost: int = Field(default=3, ge=1, le=10)
    """Argon2id iterations per password hash."""
    argon2_memory_cost_kib: int = Field(default=65_536, ge=1_024, le=1_048_576)
    """Argon2id memory per password hash, in KiB."""
    argon2_parallelism: int = Field(default=4, ge=1, le=16)
    """Argon2id lanes per password hash."""
    metrics_token: SecretStr | None = None
    """Bearer token for `/metrics` (16+ characters); required in production when metrics are on."""
    mfa_required_for_staff: bool = False
    """Staff must use two-factor authentication; until they enrol they can only manage their own sign-in (required in production)."""
    mfa_challenge_ttl_seconds: int = Field(default=300, ge=60, le=900)
    """How long the second login step (the code prompt) stays valid after a correct password."""

    # --- rate limits (requests per window) --------------------------------------------------------
    rl_login_per_ip_per_minute: int = Field(default=20, ge=1)
    """Login attempts per client IP per minute."""
    rl_login_per_account_per_15_minutes: int = Field(default=10, ge=1)
    """Login attempts per account (e-mail) per 15 minutes."""
    rl_password_reset_per_hour: int = Field(default=5, ge=1)
    """Password-reset requests per client IP, and per e-mail address, per hour."""
    rl_refresh_per_minute: int = Field(default=30, ge=1)
    """Token refreshes per client IP per minute."""
    rl_api_per_user_per_minute: int = Field(default=120, ge=1)
    """Authenticated API requests per user per minute."""
    rl_api_per_ip_per_minute: int = Field(default=300, ge=1)
    """API requests per client IP per minute."""
    rl_llm_per_user_per_minute: int = Field(default=10, ge=1)
    """Messages to the assistant per user per minute."""
    rl_llm_per_user_per_day: int = Field(default=300, ge=1)
    """Messages to the assistant per user per day."""
    rl_upload_per_hour: int = Field(default=20, ge=1)
    """Knowledge-base uploads per administrator per hour."""
    rl_admin_per_minute: int = Field(default=60, ge=1)
    """Administrative API requests per user per minute."""
    rl_privacy_export_per_day: int = Field(default=5, ge=1)
    """Personal-data exports per user per day."""

    # --- llm --------------------------------------------------------------------------------------------
    llm_provider: LLMProviderName = LLMProviderName.OFFLINE
    """`offline` (deterministic, grounded, no network) or `anthropic` (Claude)."""
    anthropic_api_key: SecretStr | None = None
    """Claude API key; required when the provider is `anthropic`."""
    anthropic_base_url: str | None = None
    """Alternative Claude API endpoint (HTTPS only), for example a company gateway."""
    llm_agent_model: str = "claude-opus-5-5"
    """Model that writes replies and calls tools."""
    llm_classifier_model: str = "claude-haiku-4-5"
    """Model that classifies intent, priority and sentiment (structured output)."""
    llm_summary_model: str = "claude-haiku-4-5"
    """Model that summarises long conversations."""
    llm_agent_effort: Effort = "low"
    """Effort level of the agent model (`output_config.effort`)."""
    llm_agent_max_tokens: int = Field(default=4_096, ge=512, le=32_000)
    """Output-token cap per agent call."""
    llm_classifier_max_tokens: int = Field(default=1_024, ge=256, le=4_096)
    """Output-token cap per classification call."""
    llm_summary_max_tokens: int = Field(default=1_024, ge=256, le=4_096)
    """Output-token cap per summary call."""
    llm_request_timeout_seconds: float = Field(default=45.0, gt=0, le=300)
    """Timeout per model request."""
    llm_max_retries: int = Field(default=2, ge=0, le=5)
    """SDK retries for transient failures (429, 5xx, connection errors) with backoff."""
    llm_refusal_fallback_enabled: bool = True
    """Let the API retry a refused request on a fallback model (server-side fallback)."""
    llm_fallback_to_offline: bool = True
    """Answer with the offline model when Claude is unavailable, over budget or circuit-broken."""
    llm_prompt_caching: bool = True
    """Cache the stable prompt prefix (system prompt and tool definitions)."""
    llm_circuit_failure_threshold: int = Field(default=5, ge=1, le=100)
    """Consecutive provider failures that open the circuit breaker."""
    llm_circuit_reset_seconds: float = Field(default=30.0, gt=0, le=3_600)
    """How long the circuit stays open before a trial request."""
    llm_user_daily_token_budget: int = Field(default=200_000, ge=1_000)
    """Tokens (input + output) one user may consume per day."""
    llm_global_daily_cost_limit_usd: float = Field(default=25.0, gt=0)
    """Estimated model spend allowed per day across all users, in USD."""

    # --- agent --------------------------------------------------------------------------------------------
    agent_max_iterations: int = Field(default=4, ge=1, le=10)
    """Model calls per customer turn (bounds the tool loop)."""
    agent_max_tool_calls: int = Field(default=6, ge=1, le=20)
    """Tool executions per customer turn."""
    agent_turn_timeout_seconds: float = Field(default=60.0, gt=0, le=300)
    """Wall-clock limit for one customer turn."""
    agent_tool_timeout_seconds: float = Field(default=5.0, gt=0, le=60)
    """Timeout per tool execution."""
    agent_min_confidence: float = Field(default=0.55, ge=0.0, le=1.0)
    """Classification confidence below which the assistant asks a clarifying question."""
    agent_history_messages: int = Field(default=8, ge=0, le=40)
    """Recent messages sent to the model verbatim (older ones are summarised)."""
    agent_summary_trigger_messages: int = Field(default=14, ge=4, le=200)
    """Conversation length that triggers a rolling summary."""
    agent_max_message_chars: int = Field(default=4_000, ge=200, le=20_000)
    """Longest accepted customer message."""
    agent_max_response_chars: int = Field(default=2_500, ge=200, le=20_000)
    """Longest reply the assistant may send (longer replies are truncated)."""
    agent_suspicious_escalation_threshold: int = Field(default=3, ge=1, le=50)
    """Manipulation attempts in one conversation before a human takes over."""
    agent_failure_escalation_threshold: int = Field(default=2, ge=1, le=20)
    """Failed answers in one conversation before a human takes over."""
    agent_allowed_link_domains: CommaList = Field(
        default_factory=lambda: ["help.acme.example", "support.acme.example"]
    )
    """Domains the assistant may link to; any other link is removed from replies."""
    agent_action_ttl_seconds: int = Field(default=900, ge=60, le=86_400)
    """How long a proposed action waits for the customer's confirmation."""
    agent_max_tickets_per_day: int = Field(default=5, ge=1, le=100)
    """Support tickets the assistant may open per customer per day."""

    # --- retrieval-augmented generation ----------------------------------------------------------------
    qdrant_url: str | None = None
    """Qdrant server URL; required in production."""
    qdrant_api_key: SecretStr | None = None
    """Qdrant API key."""
    qdrant_location: str = ":memory:"
    """Embedded Qdrant when no URL is set: `:memory:` or a directory (development)."""
    qdrant_collection: str = Field(default="aegis_knowledge", pattern=r"^[a-z][a-z0-9_]{2,62}$")
    """Collection that holds the knowledge-base chunks."""
    embedding_provider: EmbeddingProviderName = EmbeddingProviderName.HASHING
    """`hashing` (local, deterministic, no network) or `voyage` (Voyage AI)."""
    embedding_dimensions: int = Field(default=512, ge=64, le=4_096)
    """Vector size; must match the collection (re-index after changing it)."""
    voyage_api_key: SecretStr | None = None
    """Voyage AI API key; required when the provider is `voyage`."""
    voyage_model: str = "voyage-3.5"
    """Voyage AI embedding model."""
    voyage_base_url: str = "https://api.voyageai.com"
    """Voyage AI endpoint (HTTPS only; the only host the embedder may call)."""
    rag_top_k: int = Field(default=5, ge=1, le=20)
    """Chunks placed into the model's context per turn."""
    rag_candidate_k: int = Field(default=15, ge=1, le=100)
    """Candidates fetched from the index before filtering and ranking."""
    rag_score_threshold: float = Field(default=0.2, ge=0.0, le=1.0)
    """Minimum similarity for a chunk to be used."""
    rag_max_context_chars: int = Field(default=6_000, ge=500, le=50_000)
    """Character budget for retrieved context per turn."""
    rag_max_chunks_per_document: int = Field(default=2, ge=1, le=10)
    """Chunks a single document may contribute to one answer."""
    rag_chunk_chars: int = Field(default=1_000, ge=200, le=8_000)
    """Target chunk size when indexing."""
    rag_chunk_overlap_chars: int = Field(default=150, ge=0, le=2_000)
    """Overlap between consecutive chunks."""
    rag_max_chunks_per_upload: int = Field(default=400, ge=1, le=5_000)
    """Chunks one upload may produce; larger documents are rejected."""

    # --- email ---------------------------------------------------------------------------------------------
    email_backend: EmailBackend = EmailBackend.DEV_MAILBOX
    """`smtp`, `dev_mailbox` (writes e-mails to files; development only) or `disabled`."""
    email_from: str = "Acme Support <no-reply@acme.example>"
    """Sender of password-reset e-mails."""
    mailbox_dir: str = "var/mailbox"
    """Directory of the development mailbox."""
    smtp_host: str | None = None
    """SMTP server; required for the `smtp` backend (STARTTLS with certificate checks)."""
    smtp_port: int = Field(default=587, ge=1, le=65_535)
    """SMTP port."""
    smtp_username: str | None = None
    """SMTP user name."""
    smtp_password: SecretStr | None = None
    """SMTP password."""
    smtp_timeout_seconds: float = Field(default=10.0, gt=0, le=120)
    """SMTP connection timeout."""

    # --- payments -----------------------------------------------------------------------------------------
    payment_provider: PaymentProviderName = PaymentProviderName.SIMULATED
    """`simulated` (moves no money; development and demos) or `stripe`; production refuses `simulated`."""
    stripe_api_key: SecretStr | None = None
    """Stripe secret key; use a restricted key that may only create and read refunds."""
    stripe_webhook_secret: SecretStr | None = None
    """Signing secret of the Stripe webhook endpoint that reports refund results."""
    stripe_base_url: str = "https://api.stripe.com"
    """Stripe API endpoint (HTTPS only; the only host the payment adapter may call)."""

    # --- privacy -------------------------------------------------------------------------------------------
    conversation_retention_days: int = Field(default=0, ge=0, le=3_650)
    """Erase the text of closed conversations older than this many days (0 keeps it)."""

    # --- misc ---------------------------------------------------------------------------------------------
    metrics_enabled: bool = True
    """Expose Prometheus metrics at `/metrics`."""
    idempotency_ttl_seconds: int = Field(default=86_400, ge=60, le=604_800)
    """How long an `Idempotency-Key` and its stored response are kept."""
    worker_heartbeat_file: str | None = None
    """File the worker touches after every loop; `aegis healthcheck --worker` checks its age."""

    # ------------------------------------------------------------------------------------------------------
    _split_lists = field_validator(
        "allowed_hosts",
        "cors_origins",
        "trusted_proxies",
        "agent_allowed_link_domains",
        mode="before",
    )(_split_csv)

    @field_validator("jwt_secret")
    @classmethod
    def _jwt_secret_strength(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        if len(raw) < 32:
            msg = "AEGIS_JWT_SECRET must be at least 32 characters (use `aegis generate-secrets`)"
            raise ValueError(msg)
        if len(set(raw)) < 8:
            msg = "AEGIS_JWT_SECRET has too little variety to be a random secret"
            raise ValueError(msg)
        return value

    @field_validator("metrics_token")
    @classmethod
    def _metrics_token_strength(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and len(value.get_secret_value()) < 16:
            msg = (
                "AEGIS_METRICS_TOKEN must be at least 16 characters (use `aegis generate-secrets`)"
            )
            raise ValueError(msg)
        return value

    @field_validator("field_encryption_keys")
    @classmethod
    def _fernet_keys(cls, value: SecretStr) -> SecretStr:
        keys = [k.strip() for k in value.get_secret_value().split(",") if k.strip()]
        if not keys:
            msg = "AEGIS_FIELD_ENCRYPTION_KEYS must contain at least one Fernet key"
            raise ValueError(msg)
        if not all(_is_valid_fernet_key(k) for k in keys):
            msg = "AEGIS_FIELD_ENCRYPTION_KEYS entries must be url-safe base64 32-byte Fernet keys"
            raise ValueError(msg)
        return value

    @model_validator(mode="after")
    def _cross_field_rules(self) -> Self:
        if self.rag_chunk_overlap_chars >= self.rag_chunk_chars:
            msg = "rag_chunk_overlap_chars must be smaller than rag_chunk_chars"
            raise ValueError(msg)
        if self.rag_candidate_k < self.rag_top_k:
            msg = "rag_candidate_k must be >= rag_top_k"
            raise ValueError(msg)
        if self.llm_provider is LLMProviderName.ANTHROPIC and self.anthropic_api_key is None:
            msg = "AEGIS_ANTHROPIC_API_KEY is required when AEGIS_LLM_PROVIDER=anthropic"
            raise ValueError(msg)
        if self.embedding_provider is EmbeddingProviderName.VOYAGE and self.voyage_api_key is None:
            msg = "AEGIS_VOYAGE_API_KEY is required when AEGIS_EMBEDDING_PROVIDER=voyage"
            raise ValueError(msg)
        if self.email_backend is EmailBackend.SMTP and not self.smtp_host:
            msg = "AEGIS_SMTP_HOST is required when AEGIS_EMAIL_BACKEND=smtp"
            raise ValueError(msg)
        if self.payment_provider is PaymentProviderName.STRIPE and (
            self.stripe_api_key is None or self.stripe_webhook_secret is None
        ):
            msg = "AEGIS_STRIPE_API_KEY and AEGIS_STRIPE_WEBHOOK_SECRET are required when AEGIS_PAYMENT_PROVIDER=stripe"
            raise ValueError(msg)
        for url in (self.anthropic_base_url, self.voyage_base_url, self.stripe_base_url):
            if url is not None and not url.startswith("https://"):
                msg = "provider base URLs must use https://"
                raise ValueError(msg)
        if self.is_production:
            self._enforce_production_rules()
        return self

    def _enforce_production_rules(self) -> None:
        problems: list[str] = []
        if self.is_sqlite:
            problems.append("SQLite is not allowed in production; use PostgreSQL")
        if self.database_echo:
            problems.append("AEGIS_DATABASE_ECHO would log SQL parameters (customer data)")
        if self.redis_url is None:
            problems.append("AEGIS_REDIS_URL is required (rate limits and locks must be shared)")
        if not self.qdrant_url:
            problems.append(
                "AEGIS_QDRANT_URL is required (the local vector index is single-process)"
            )
        if "*" in self.allowed_hosts or not self.allowed_hosts:
            problems.append("AEGIS_ALLOWED_HOSTS must list explicit host names")
        if "*" in self.cors_origins:
            problems.append("AEGIS_CORS_ORIGINS must not contain '*'")
        if any(not origin.startswith("https://") for origin in self.cors_origins):
            problems.append("AEGIS_CORS_ORIGINS must be https:// origins in production")
        if self.email_backend is EmailBackend.DEV_MAILBOX:
            problems.append("the development mailbox writes reset links to disk")
        if self.metrics_enabled and self.metrics_token is None:
            problems.append("AEGIS_METRICS_TOKEN is required when metrics are enabled")
        if not self.hsts_enabled:
            problems.append("AEGIS_HSTS_ENABLED must be true behind TLS in production")
        if self.log_level == "DEBUG":
            problems.append("DEBUG logging is not allowed in production")
        if not self.log_json:
            problems.append("AEGIS_LOG_JSON must be true in production (no tracebacks in logs)")
        if not self.mfa_required_for_staff:
            problems.append("AEGIS_MFA_REQUIRED_FOR_STAFF must be true in production")
        if self.payment_provider is PaymentProviderName.SIMULATED:
            problems.append("the simulated payment provider moves no money; configure a real one")
        secret = self.jwt_secret.get_secret_value().lower()
        if any(marker in secret for marker in _PLACEHOLDER_MARKERS):
            problems.append("AEGIS_JWT_SECRET looks like a placeholder")
        if problems:
            raise ValueError("unsafe production configuration: " + "; ".join(problems))

    # --- derived values ----------------------------------------------------------------------------------
    @property
    def is_production(self) -> bool:
        return self.env is Environment.PRODUCTION

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.get_secret_value().startswith("sqlite")

    @property
    def docs_enabled(self) -> bool:
        if self.api_docs_enabled is not None:
            return self.api_docs_enabled
        return not self.is_production

    @property
    def encryption_keys(self) -> list[str]:
        return [
            k.strip() for k in self.field_encryption_keys.get_secret_value().split(",") if k.strip()
        ]


SECRETS_DIR_VARIABLE = "AEGIS_SECRETS_DIR"


def load_settings() -> Settings:
    """Read settings from the environment, ``.env`` and ``AEGIS_SECRETS_DIR``; raises if invalid.

    Precedence (highest first): environment variables, ``.env``, secret files.
    """
    secrets_dir = os.environ.get(SECRETS_DIR_VARIABLE, "").strip()
    if not secrets_dir:
        return Settings()  # required fields come from the environment
    if not Path(secrets_dir).is_dir():
        msg = f"{SECRETS_DIR_VARIABLE} is set but is not a directory"
        raise ValueError(msg)
    return Settings(_secrets_dir=secrets_dir)
