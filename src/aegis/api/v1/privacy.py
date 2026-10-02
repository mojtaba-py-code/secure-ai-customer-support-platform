"""Data-subject requests of the signed-in customer: export and erasure request."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Response, status

from aegis.api.deps import ContainerDep, ServicesDep, enforce_rate_limit, require
from aegis.api.v1 import API_V1_PREFIX
from aegis.schemas.privacy import ErasureRequestOut, PrivacyExport
from aegis.security.principal import Principal
from aegis.security.rbac import Permission

router = APIRouter(prefix=f"{API_V1_PREFIX}/privacy", tags=["privacy"])

Exporter = Annotated[Principal, Depends(require(Permission.PRIVACY_EXPORT_OWN))]
Requester = Annotated[Principal, Depends(require(Permission.TICKET_CREATE_OWN))]


@router.get("/export", response_model=PrivacyExport)
async def export_my_data(
    principal: Exporter, container: ContainerDep, services: ServicesDep, response: Response
) -> PrivacyExport:
    """Everything the platform stores about you, as one JSON document."""
    await enforce_rate_limit(
        container, container.rate_limits.privacy_export, f"user:{principal.user_id}"
    )
    response.headers["Content-Disposition"] = 'attachment; filename="my-data.json"'
    return await services.privacy.export(principal)


@router.post(
    "/erasure-request", status_code=status.HTTP_202_ACCEPTED, response_model=ErasureRequestOut
)
async def request_erasure(principal: Requester, services: ServicesDep) -> ErasureRequestOut:
    """Ask for your personal data to be erased; the privacy team verifies and completes it."""
    ticket = await services.privacy.request_erasure(principal)
    return ErasureRequestOut(
        ticket_number=ticket.ticket_number,
        detail="Your request was received. We will confirm by e-mail once it is completed.",
    )
