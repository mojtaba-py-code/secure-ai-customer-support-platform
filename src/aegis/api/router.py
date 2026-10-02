"""Aggregates the versioned API routers."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from aegis.api.deps import ip_rate_limit, reject_unknown_query_parameters
from aegis.api.v1 import (
    API_V1_PREFIX,
    admin,
    auth,
    commerce,
    conversations,
    desk,
    privacy,
    tickets,
    webhooks,
)
from aegis.schemas.common import Problem

V1_ROUTERS: tuple[APIRouter, ...] = (
    auth.router,
    conversations.router,
    commerce.orders_router,
    commerce.refunds_router,
    tickets.router,
    desk.router,
    privacy.router,
    admin.router,
    webhooks.router,
)
#: Dependencies applied to every /api/v1 route (before authentication): a per-client-IP limit,
#: so even requests with invalid tokens are throttled, then strict query-string validation.
V1_DEPENDENCIES = (Depends(ip_rate_limit), Depends(reject_unknown_query_parameters))

_PROBLEM: dict[str, Any] = {
    "model": Problem,
    "content": {"application/problem+json": {}},
}
ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    status: {**_PROBLEM, "description": description}
    for status, description in (
        (400, "Malformed request"),
        (401, "Authentication required or failed"),
        (403, "The role lacks the required permission"),
        (404, "Not found (or not yours)"),
        (409, "Conflicts with the current state"),
        (413, "Request body too large"),
        (415, "Unsupported content type"),
        (422, "Validation error (the submitted values are never echoed)"),
        (429, "Rate limit or model budget exceeded (see Retry-After)"),
        (500, "Unexpected error (only the request id is returned)"),
        (503, "A dependency is temporarily unavailable"),
    )
}

# No prefix here: each v1 router already carries /api/v1 (see aegis.api.v1).
api_router = APIRouter(dependencies=list(V1_DEPENDENCIES), responses=ERROR_RESPONSES)
for _router in V1_ROUTERS:
    api_router.include_router(_router)

UPLOAD_PATHS = (f"{API_V1_PREFIX}/admin/knowledge-base/documents",)
