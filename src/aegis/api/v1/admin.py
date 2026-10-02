"""Administration: staff accounts, the knowledge base, the audit trail and model usage."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from decimal import Decimal
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, Query, Response, UploadFile, status

from aegis.api.deps import (
    ContainerDep,
    Limit,
    Offset,
    ServicesDep,
    enforce_rate_limit,
    require_admin,
)
from aegis.api.v1 import API_V1_PREFIX
from aegis.core.errors import PayloadTooLarge
from aegis.domain.enums import (
    AuditOutcome,
    DocumentStatus,
    KnowledgeCategory,
    KnowledgeVisibility,
    Role,
)
from aegis.schemas.admin import (
    AuditEventOut,
    DocumentOut,
    RevokedSessions,
    UsageLineOut,
    UsageSummaryOut,
    UserCreate,
    UserOut,
    UserUpdate,
)
from aegis.schemas.common import Page
from aegis.schemas.privacy import ErasureConfirmation, ErasureReportOut
from aegis.security.principal import Principal
from aegis.security.rbac import Permission

router = APIRouter(prefix=f"{API_V1_PREFIX}/admin", tags=["admin"])

UserAdmin = Annotated[Principal, Depends(require_admin(Permission.USER_MANAGE))]
KbAdmin = Annotated[Principal, Depends(require_admin(Permission.KB_MANAGE))]
Auditor = Annotated[Principal, Depends(require_admin(Permission.AUDIT_READ))]
UsageReader = Annotated[Principal, Depends(require_admin(Permission.USAGE_READ))]
Eraser = Annotated[Principal, Depends(require_admin(Permission.PRIVACY_ERASE))]


# --- users -----------------------------------------------------------------------------------------
@router.post("/users", status_code=status.HTTP_201_CREATED, response_model=UserOut)
async def create_user(body: UserCreate, principal: UserAdmin, services: ServicesDep) -> UserOut:
    user = await services.users.create_staff(
        principal,
        email=body.email,
        display_name=body.display_name,
        role=body.role,
        password=body.password,
    )
    return UserOut.model_validate(user)


@router.get("/users", response_model=Page[UserOut])
async def list_users(
    principal: UserAdmin,
    services: ServicesDep,
    role: Role | None = None,
    limit: Limit = 20,
    offset: Offset = 0,
) -> Page[UserOut]:
    users = await services.users.list_users(principal, role=role, limit=limit, offset=offset)
    return Page[UserOut](
        items=[UserOut.model_validate(u) for u in users], limit=limit, offset=offset
    )


@router.patch("/users/{user_id}", response_model=UserOut)
async def update_user(
    user_id: uuid.UUID, body: UserUpdate, principal: UserAdmin, services: ServicesDep
) -> UserOut:
    return UserOut.model_validate(
        await services.users.update(principal, user_id, role=body.role, is_active=body.is_active)
    )


@router.post("/users/{user_id}/unlock", response_model=UserOut)
async def unlock_user(user_id: uuid.UUID, principal: UserAdmin, services: ServicesDep) -> UserOut:
    return UserOut.model_validate(await services.users.unlock(principal, user_id))


@router.post("/users/{user_id}/reset-mfa", response_model=UserOut)
async def reset_mfa(user_id: uuid.UUID, principal: UserAdmin, services: ServicesDep) -> UserOut:
    """Clear a user's lost second factor (never your own); every session of the user ends."""
    return UserOut.model_validate(await services.users.reset_mfa(principal, user_id))


@router.post("/users/{user_id}/revoke-sessions", response_model=RevokedSessions)
async def revoke_sessions(
    user_id: uuid.UUID, principal: UserAdmin, services: ServicesDep
) -> RevokedSessions:
    return RevokedSessions(
        revoked_sessions=await services.users.revoke_sessions(principal, user_id)
    )


# --- data-subject requests ----------------------------------------------------------------------------
@router.post("/customers/{customer_id}/erase", response_model=ErasureReportOut)
async def erase_customer(
    customer_id: uuid.UUID,
    body: ErasureConfirmation,
    principal: Eraser,
    services: ServicesDep,
) -> ErasureReportOut:
    """Irreversibly anonymise a customer (contact data, free text, login); financial records stay."""
    report = await services.privacy.erase(principal, customer_id, confirmation=body.customer_number)
    return ErasureReportOut(
        customer_id=report.customer_id, erased_at=report.erased_at, counts=report.counts
    )


# --- knowledge base ----------------------------------------------------------------------------------
@router.post(
    "/knowledge-base/documents", status_code=status.HTTP_202_ACCEPTED, response_model=DocumentOut
)
async def upload_document(
    *,
    principal: KbAdmin,
    container: ContainerDep,
    services: ServicesDep,
    file: Annotated[UploadFile, File(description="Markdown (.md) or plain text (.txt), UTF-8")],
    title: Annotated[str, Form(min_length=3, max_length=200)],
    category: Annotated[KnowledgeCategory, Form()],
    visibility: Annotated[KnowledgeVisibility, Form()],
    slug: Annotated[str | None, Form(max_length=80)] = None,
    effective_date: Annotated[date | None, Form()] = None,
    index_now: Annotated[
        bool, Query(description="Index synchronously instead of via the worker")
    ] = False,
) -> DocumentOut:
    """Upload a document. It is screened, then indexed by the worker (or immediately with
    ``index_now``). Documents with prompt-injection indicators are quarantined until approved.
    """
    await enforce_rate_limit(container, container.rate_limits.upload, f"admin:{principal.user_id}")
    limit = container.settings.max_upload_bytes
    data = await file.read(limit + 1)
    if len(data) > limit:
        raise PayloadTooLarge(f"Documents must be at most {limit // 1024} KiB.")
    document = await services.knowledge.upload(
        principal,
        filename=file.filename,
        content_type=file.content_type,
        data=data,
        title=title,
        category=category,
        visibility=visibility,
        slug=slug,
        effective_date=effective_date,
    )
    if index_now and document.status is DocumentStatus.PENDING:
        await services.knowledge.index_document(document.id)
        document = await services.knowledge.get(principal, document.id)
    return DocumentOut.model_validate(document)


@router.get("/knowledge-base/documents", response_model=Page[DocumentOut])
async def list_documents(
    principal: KbAdmin,
    services: ServicesDep,
    status_filter: Annotated[DocumentStatus | None, Query(alias="status")] = None,
    limit: Limit = 20,
    offset: Offset = 0,
) -> Page[DocumentOut]:
    documents = await services.knowledge.list_documents(
        principal, status=status_filter, limit=limit, offset=offset
    )
    return Page[DocumentOut](
        items=[DocumentOut.model_validate(d) for d in documents], limit=limit, offset=offset
    )


@router.get("/knowledge-base/documents/{document_id}", response_model=DocumentOut)
async def get_document(
    document_id: uuid.UUID, principal: KbAdmin, services: ServicesDep
) -> DocumentOut:
    return DocumentOut.model_validate(await services.knowledge.get(principal, document_id))


@router.post("/knowledge-base/documents/{document_id}/approve", response_model=DocumentOut)
async def approve_document(
    document_id: uuid.UUID, principal: KbAdmin, services: ServicesDep
) -> DocumentOut:
    """Release a quarantined document for indexing (suspicious chunks are still dropped)."""
    return DocumentOut.model_validate(
        await services.knowledge.approve_quarantined(principal, document_id)
    )


@router.post("/knowledge-base/documents/{document_id}/reindex", response_model=DocumentOut)
async def reindex_document(
    document_id: uuid.UUID, principal: KbAdmin, services: ServicesDep
) -> DocumentOut:
    return DocumentOut.model_validate(
        await services.knowledge.request_reindex(principal, document_id)
    )


@router.delete(
    "/knowledge-base/documents/{document_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Archive a document",
    description=(
        "Soft delete: the document leaves retrieval at once (its chunks are removed from the "
        "vector index and the assistant can no longer cite it), while the record stays readable "
        "to administrators with status `archived` for the audit trail."
    ),
)
async def archive_document(
    document_id: uuid.UUID, principal: KbAdmin, services: ServicesDep
) -> Response:
    await services.knowledge.archive(principal, document_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- audit & usage ------------------------------------------------------------------------------------
@router.get("/audit-events", response_model=Page[AuditEventOut])
async def list_audit_events(
    principal: Auditor,
    container: ContainerDep,
    action: Annotated[str | None, Query(max_length=80, pattern=r"^[a-z_.]+$")] = None,
    actor_user_id: uuid.UUID | None = None,
    outcome: AuditOutcome | None = None,
    since: datetime | None = None,
    limit: Limit = 50,
    offset: Offset = 0,
) -> Page[AuditEventOut]:
    events = await container.audit.list_events(
        principal,
        action_prefix=action,
        actor_user_id=actor_user_id,
        outcome=outcome,
        since=since,
        limit=limit,
        offset=offset,
    )
    return Page[AuditEventOut](
        items=[AuditEventOut.model_validate(e) for e in events], limit=limit, offset=offset
    )


@router.get("/llm-usage", response_model=UsageSummaryOut)
async def llm_usage(
    principal: UsageReader, container: ContainerDep, days: Annotated[int, Query(ge=1, le=90)] = 7
) -> UsageSummaryOut:
    lines = await container.usage.summary(days=days)
    return UsageSummaryOut(
        days=days,
        total_cost_usd=sum((line.cost_usd for line in lines), Decimal(0)),
        lines=[UsageLineOut.model_validate(line) for line in lines],
    )
