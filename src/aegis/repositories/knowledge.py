"""Knowledge-base documents."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.domain.enums import DocumentStatus
from aegis.models import KnowledgeDocument
from aegis.repositories.common import affected_rows, clamp_page


class KnowledgeRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def add(self, document: KnowledgeDocument) -> KnowledgeDocument:
        self._session.add(document)
        return document

    async def get(self, document_id: uuid.UUID) -> KnowledgeDocument | None:
        return await self._session.get(KnowledgeDocument, document_id)

    async def get_for_update(self, document_id: uuid.UUID) -> KnowledgeDocument | None:
        stmt = (
            select(KnowledgeDocument)
            .where(KnowledgeDocument.id == document_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def get_live_by_hash(self, content_sha256: str) -> KnowledgeDocument | None:
        stmt = select(KnowledgeDocument).where(
            KnowledgeDocument.content_sha256 == content_sha256,
            KnowledgeDocument.status != DocumentStatus.ARCHIVED,
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def latest_version(self, slug: str) -> int:
        stmt = select(func.max(KnowledgeDocument.version)).where(KnowledgeDocument.slug == slug)
        return int((await self._session.execute(stmt)).scalar_one() or 0)

    async def list_documents(
        self, *, status: DocumentStatus | None, limit: int, offset: int
    ) -> list[KnowledgeDocument]:
        limit, offset = clamp_page(limit, offset)
        stmt = select(KnowledgeDocument).order_by(
            KnowledgeDocument.created_at.desc(), KnowledgeDocument.id
        )
        if status is not None:
            stmt = stmt.where(KnowledgeDocument.status == status)
        return list((await self._session.execute(stmt.limit(limit).offset(offset))).scalars())

    async def ids_with_status(self, status: DocumentStatus, *, limit: int = 100) -> list[uuid.UUID]:
        stmt = (
            select(KnowledgeDocument.id)
            .where(KnowledgeDocument.status == status)
            .order_by(KnowledgeDocument.created_at)
            .limit(limit)
        )
        return list((await self._session.execute(stmt)).scalars())

    async def claim_for_indexing(self, document_id: uuid.UUID, now: datetime) -> bool:
        """PENDING -> INDEXING, atomically, so two workers never index the same document."""
        result = await self._session.execute(
            update(KnowledgeDocument)
            .where(
                KnowledgeDocument.id == document_id,
                KnowledgeDocument.status == DocumentStatus.PENDING,
            )
            .values(status=DocumentStatus.INDEXING, updated_at=now)
        )
        return affected_rows(result) == 1

    async def other_live_versions(self, slug: str, keep_id: uuid.UUID) -> list[KnowledgeDocument]:
        stmt = select(KnowledgeDocument).where(
            KnowledgeDocument.slug == slug,
            KnowledgeDocument.id != keep_id,
            KnowledgeDocument.status == DocumentStatus.INDEXED,
        )
        return list((await self._session.execute(stmt)).scalars())

    async def reset_stale_indexing(self, older_than: datetime) -> int:
        """Return documents stuck in INDEXING (worker crashed) to PENDING."""
        result = await self._session.execute(
            update(KnowledgeDocument)
            .where(
                KnowledgeDocument.status == DocumentStatus.INDEXING,
                KnowledgeDocument.updated_at < older_than,
            )
            .values(status=DocumentStatus.PENDING)
        )
        return affected_rows(result)
