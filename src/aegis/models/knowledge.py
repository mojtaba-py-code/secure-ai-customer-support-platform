"""Knowledge-base documents (the source of truth; the vector index is derived from these rows)."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any

from sqlalchemy import Date, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column

from aegis.db.base import Base, JSONType, TimestampMixin, UUIDPrimaryKeyMixin, str_enum
from aegis.domain.enums import DocumentStatus, KnowledgeCategory, KnowledgeVisibility


class KnowledgeDocument(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "knowledge_documents"

    title: Mapped[str] = mapped_column(String(200))
    slug: Mapped[str] = mapped_column(String(120))
    category: Mapped[KnowledgeCategory] = mapped_column(str_enum(KnowledgeCategory, "kb_category"))
    visibility: Mapped[KnowledgeVisibility] = mapped_column(
        str_enum(KnowledgeVisibility, "kb_visibility")
    )
    version: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[DocumentStatus] = mapped_column(
        str_enum(DocumentStatus, "kb_status"), default=DocumentStatus.PENDING
    )
    source_filename: Mapped[str] = mapped_column(String(120))
    mime_type: Mapped[str] = mapped_column(String(40))
    size_bytes: Mapped[int] = mapped_column(Integer)
    content_sha256: Mapped[str] = mapped_column(String(64))
    content: Mapped[str] = mapped_column(Text)
    injection_score: Mapped[float] = mapped_column(Float, default=0.0)
    injection_categories: Mapped[list[str]] = mapped_column(JSONType, default=list)
    chunk_count: Mapped[int] = mapped_column(Integer, default=0)
    error_code: Mapped[str | None] = mapped_column(String(40))
    uploaded_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    reviewed_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    effective_date: Mapped[date | None] = mapped_column(Date)
    indexed_at: Mapped[datetime | None]
    meta: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)

    __table_args__ = (
        UniqueConstraint("slug", "version", name="uq_knowledge_documents_slug_version"),
        Index("ix_knowledge_documents_status", "status"),
        Index(
            "uq_knowledge_documents_live_content",
            "content_sha256",
            unique=True,
            postgresql_where=text("status <> 'archived'"),
            sqlite_where=text("status <> 'archived'"),
        ),
    )
