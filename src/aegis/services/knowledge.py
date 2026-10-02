"""Knowledge-base lifecycle: upload -> screening -> (quarantine | pending) -> indexing -> retrieval.

Security controls on the ingestion path:

* uploads are validated by :mod:`aegis.security.uploads` (type, size, encoding, binary sniffing);
* documents are stored in the database - never on a path derived from user input;
* each document is screened for prompt-injection indicators; suspicious documents are
  **quarantined** and never indexed until an administrator explicitly approves them, and even
  approved documents have their suspicious *chunks* dropped at indexing time;
* indexing runs in the worker (or the CLI), bounded by a chunk cap per document;
* a newer version of the same document (same ``slug``) archives the older one and removes its
  vectors, so retrieval never serves two conflicting versions of one policy.
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass
from datetime import date, timedelta

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.core.errors import Conflict, DependencyUnavailable, NotFound, ValidationFailed
from aegis.core.time import Clock, utc_now
from aegis.domain.enums import AuditOutcome, DocumentStatus, KnowledgeCategory, KnowledgeVisibility
from aegis.models import KnowledgeDocument
from aegis.observability import metrics
from aegis.rag.chunking import chunk_markdown
from aegis.rag.embeddings import Embedder
from aegis.rag.vector_store import ChunkPayload, QdrantVectorStore
from aegis.repositories.knowledge import KnowledgeRepository
from aegis.security.injection import PromptInjectionDetector
from aegis.security.principal import Principal
from aegis.security.rbac import Permission
from aegis.security.text import normalize_text
from aegis.security.uploads import validate_upload
from aegis.services.audit import AuditService
from aegis.services.authz import require

logger = logging.getLogger(__name__)

_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{2,79}$")


@dataclass(frozen=True, slots=True)
class ChunkingSettings:
    chunk_chars: int
    overlap_chars: int
    max_chunks: int


def slugify(title: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", normalize_text(title).lower()).strip("-")
    return slug[:80] or "document"


class KnowledgeService:
    def __init__(
        self,
        session: AsyncSession,
        *,
        store: QdrantVectorStore,
        embedder: Embedder,
        detector: PromptInjectionDetector,
        chunking: ChunkingSettings,
        max_upload_bytes: int,
        audit: AuditService,
        clock: Clock = utc_now,
    ) -> None:
        self._session = session
        self._repo = KnowledgeRepository(session)
        self._store = store
        self._embedder = embedder
        self._detector = detector
        self._chunking = chunking
        self._max_upload_bytes = max_upload_bytes
        self._audit = audit
        self._clock = clock

    # --- upload / review ----------------------------------------------------------------------------
    async def upload(
        self,
        principal: Principal | None,
        *,
        filename: str | None,
        content_type: str | None,
        data: bytes,
        title: str,
        category: KnowledgeCategory,
        visibility: KnowledgeVisibility,
        slug: str | None = None,
        effective_date: date | None = None,
    ) -> KnowledgeDocument:
        """Store a validated document. ``principal=None`` is used only by the trusted seed CLI."""
        if principal is not None:
            require(principal, Permission.KB_MANAGE)
        validated = validate_upload(
            filename=filename,
            declared_content_type=content_type,
            data=data,
            max_bytes=self._max_upload_bytes,
        )
        clean_title = normalize_text(title)[:200]
        if len(clean_title) < 3:
            raise ValidationFailed("Please give the document a title.")
        doc_slug = slug or slugify(clean_title)
        if not _SLUG.fullmatch(doc_slug):
            raise ValidationFailed(
                "The slug may contain lowercase letters, digits and hyphens (3-80 characters)."
            )
        if await self._repo.get_live_by_hash(validated.sha256) is not None:
            raise Conflict("An identical document is already in the knowledge base.")

        assessment = self._detector.assess(validated.text)
        status = DocumentStatus.QUARANTINED if assessment.is_suspicious else DocumentStatus.PENDING
        document = self._repo.add(
            KnowledgeDocument(
                title=clean_title,
                slug=doc_slug,
                category=category,
                visibility=visibility,
                version=await self._repo.latest_version(doc_slug) + 1,
                status=status,
                source_filename=validated.safe_filename,
                mime_type=validated.mime_type,
                size_bytes=validated.size_bytes,
                content_sha256=validated.sha256,
                content=validated.text,
                injection_score=assessment.score,
                injection_categories=list(assessment.categories),
                uploaded_by_user_id=principal.user_id if principal else None,
                effective_date=effective_date,
            )
        )
        try:
            await self._session.commit()
        except IntegrityError as exc:
            await self._session.rollback()
            raise Conflict(
                "This document conflicts with an existing version; please retry."
            ) from exc
        if status is DocumentStatus.QUARANTINED:
            metrics.security_event("kb_document_quarantined")
        await self._audit.record(
            "kb.upload",
            outcome=AuditOutcome.SUCCESS,
            actor=principal,
            actor_role=None if principal else "system",
            resource_type="knowledge_document",
            resource_id=document.id,
            details={
                "status": status.value,
                "visibility": visibility.value,
                "injection_score": assessment.score,
                "injection_categories": list(assessment.categories),
            },
        )
        return document

    async def approve_quarantined(
        self, principal: Principal, document_id: uuid.UUID
    ) -> KnowledgeDocument:
        require(principal, Permission.KB_MANAGE)
        document = await self._repo.get_for_update(document_id)
        if document is None:
            raise NotFound
        if document.status is not DocumentStatus.QUARANTINED:
            raise Conflict("Only quarantined documents need approval.")
        document.status = DocumentStatus.PENDING
        document.reviewed_by_user_id = principal.user_id
        await self._session.commit()
        await self._audit.record(
            "kb.approve_quarantined",
            outcome=AuditOutcome.SUCCESS,
            actor=principal,
            resource_type="knowledge_document",
            resource_id=document.id,
            details={"injection_score": document.injection_score},
        )
        return document

    async def get(self, principal: Principal, document_id: uuid.UUID) -> KnowledgeDocument:
        require(principal, Permission.KB_MANAGE)
        document = await self._repo.get(document_id)
        if document is None:
            raise NotFound
        return document

    async def list_documents(
        self, principal: Principal, *, status: DocumentStatus | None, limit: int, offset: int
    ) -> list[KnowledgeDocument]:
        require(principal, Permission.KB_MANAGE)
        return await self._repo.list_documents(status=status, limit=limit, offset=offset)

    async def archive(self, principal: Principal, document_id: uuid.UUID) -> KnowledgeDocument:
        require(principal, Permission.KB_MANAGE)
        document = await self._repo.get_for_update(document_id)
        if document is None:
            raise NotFound
        await self._store.delete_document(str(document.id))
        document.status = DocumentStatus.ARCHIVED
        document.chunk_count = 0
        await self._session.commit()
        await self._audit.record(
            "kb.archive",
            outcome=AuditOutcome.SUCCESS,
            actor=principal,
            resource_type="knowledge_document",
            resource_id=document.id,
        )
        return document

    async def request_reindex(
        self, principal: Principal, document_id: uuid.UUID
    ) -> KnowledgeDocument:
        require(principal, Permission.KB_MANAGE)
        document = await self._repo.get_for_update(document_id)
        if document is None:
            raise NotFound
        if document.status not in (DocumentStatus.INDEXED, DocumentStatus.FAILED):
            raise Conflict("Only indexed or failed documents can be re-indexed.")
        document.status = DocumentStatus.PENDING
        await self._session.commit()
        return document

    # --- indexing (worker / CLI) ------------------------------------------------------------------------
    async def index_pending(self, *, limit: int = 20) -> int:
        await self._store.ensure_collection()
        await self._repo.reset_stale_indexing(self._clock() - timedelta(minutes=15))
        await self._session.commit()
        indexed = 0
        for document_id in await self._repo.ids_with_status(DocumentStatus.PENDING, limit=limit):
            if await self.index_document(document_id):
                indexed += 1
        return indexed

    async def index_document(self, document_id: uuid.UUID) -> bool:
        if not await self._repo.claim_for_indexing(document_id, self._clock()):
            await self._session.rollback()
            return False
        await self._session.commit()
        document = await self._repo.get(document_id)
        if document is None:
            return False
        try:
            chunk_count, dropped = await self._embed_and_store(document)
        except DependencyUnavailable as exc:
            await self._session.rollback()
            document = await self._repo.get(document_id)
            if document is not None:
                document.status = DocumentStatus.PENDING
                document.error_code = "dependency_unavailable"
                await self._session.commit()
            logger.warning(
                "indexing deferred", extra={"event": "kb.index_deferred", "error": exc.log_message}
            )
            return False
        except Exception:
            await self._session.rollback()
            document = await self._repo.get(document_id)
            if document is not None:
                document.status = DocumentStatus.FAILED
                document.error_code = "indexing_failed"
                await self._session.commit()
            logger.exception(
                "indexing failed",
                extra={"event": "kb.index_failed", "document_id": str(document_id)},
            )
            return False

        document.status = DocumentStatus.INDEXED
        document.chunk_count = chunk_count
        document.error_code = None
        document.indexed_at = self._clock()
        document.meta = {**(document.meta or {}), "chunks_dropped_for_injection": dropped}
        for older in await self._repo.other_live_versions(document.slug, document.id):
            if older.version < document.version:
                await self._store.delete_document(str(older.id))
                older.status = DocumentStatus.ARCHIVED
                older.chunk_count = 0
        await self._session.commit()
        await self._audit.record(
            "kb.indexed",
            outcome=AuditOutcome.SUCCESS,
            actor_role="system",
            resource_type="knowledge_document",
            resource_id=document.id,
            details={"chunks": chunk_count, "dropped": dropped},
        )
        return True

    async def _embed_and_store(self, document: KnowledgeDocument) -> tuple[int, int]:
        chunks = chunk_markdown(
            document.content,
            max_chars=self._chunking.chunk_chars,
            overlap_chars=self._chunking.overlap_chars,
            max_chunks=self._chunking.max_chunks,
        )
        safe = [c for c in chunks if not self._detector.assess(c.text).is_suspicious]
        dropped = len(chunks) - len(safe)
        if dropped:
            metrics.security_event("kb_chunk_dropped")
        await self._store.delete_document(str(document.id))
        if not safe:
            return 0, dropped
        vectors = await self._embedder.embed_documents(
            [f"{document.title}\n{c.section}\n{c.text}" for c in safe]
        )
        await self._store.upsert(
            [
                (
                    ChunkPayload(
                        document_id=str(document.id),
                        chunk_index=chunk.index,
                        title=document.title,
                        section=chunk.section,
                        text=chunk.text,
                        category=document.category.value,
                        visibility=document.visibility.value,
                        slug=document.slug,
                        version=document.version,
                    ),
                    vector,
                )
                for chunk, vector in zip(safe, vectors, strict=True)
            ]
        )
        return len(safe), dropped

    async def reconcile_index(self) -> int:
        """Re-index everything when the vector store is empty (e.g. in-memory mode after restart)."""
        await self._store.ensure_collection()
        if await self._store.count() > 0:
            return 0
        indexed_ids = await self._repo.ids_with_status(DocumentStatus.INDEXED, limit=1_000)
        for document_id in indexed_ids:
            document = await self._repo.get(document_id)
            if document is not None:
                document.status = DocumentStatus.PENDING
        await self._session.commit()
        return await self.index_pending(limit=1_000)
