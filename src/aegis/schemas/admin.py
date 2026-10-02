"""Administration schemas: users, knowledge base, audit trail, model usage."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from decimal import Decimal
from typing import Annotated, Any

from pydantic import EmailStr, Field, StrictBool, StringConstraints

from aegis.domain.enums import (
    AuditOutcome,
    DocumentStatus,
    KnowledgeCategory,
    KnowledgeVisibility,
    Role,
)
from aegis.schemas.common import RequestModel, ResponseModel


class UserCreate(RequestModel):
    email: EmailStr = Field(max_length=254)
    display_name: Annotated[str, StringConstraints(min_length=2, max_length=120)]
    role: Role
    password: Annotated[
        str, StringConstraints(min_length=1, max_length=128, strip_whitespace=False)
    ]


class UserUpdate(RequestModel):
    role: Role | None = None
    is_active: StrictBool | None = None  # a JSON boolean: 0, "no" or "false" are rejected


class UserOut(ResponseModel):
    id: uuid.UUID
    email: str
    display_name: str
    role: Role
    is_active: bool
    locked_until: datetime | None
    last_login_at: datetime | None
    mfa_enabled_at: datetime | None
    created_at: datetime


class RevokedSessions(ResponseModel):
    revoked_sessions: int


class DocumentOut(ResponseModel):
    id: uuid.UUID
    title: str
    slug: str
    category: KnowledgeCategory
    visibility: KnowledgeVisibility
    version: int
    status: DocumentStatus
    source_filename: str
    size_bytes: int
    chunk_count: int
    injection_score: float
    injection_categories: list[str]
    error_code: str | None
    effective_date: date | None
    created_at: datetime
    indexed_at: datetime | None


class AuditEventOut(ResponseModel):
    id: uuid.UUID
    occurred_at: datetime
    actor_user_id: uuid.UUID | None
    actor_role: str | None
    action: str
    resource_type: str | None
    resource_id: str | None
    outcome: AuditOutcome
    request_id: str | None
    ip_address: str | None
    details: dict[str, Any]


class UsageLineOut(ResponseModel):
    model: str
    task: str
    calls: int
    input_tokens: int
    output_tokens: int
    cost_usd: Decimal


class UsageSummaryOut(ResponseModel):
    days: int
    total_cost_usd: Decimal
    lines: list[UsageLineOut]
