"""Liveness, readiness and Prometheus metrics.

Readiness reports component status names only ("ok"/"unavailable") - no hostnames, versions or
error strings. ``/metrics`` requires ``Authorization: Bearer <AEGIS_METRICS_TOKEN>`` whenever a
token is configured (mandatory in production), compared in constant time.
"""

from __future__ import annotations

import asyncio
import hmac

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST
from sqlalchemy import text

from aegis.api.deps import ContainerDep
from aegis.core.errors import AuthenticationFailed, NotFound
from aegis.observability.metrics import render_metrics

router = APIRouter(tags=["health"])


@router.get("/health/live")
async def live() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/health/ready")
async def ready(container: ContainerDep) -> JSONResponse:
    async def database() -> bool:
        async with container.engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
        return True

    checks: dict[str, str] = {}
    for name, probe in (
        ("database", database),
        ("cache", container.kv.ping),
        ("vector_store", container.vector_store.healthy),
    ):
        try:
            async with asyncio.timeout(3):
                ok = await probe()
        except Exception:  # noqa: BLE001 - readiness must answer whatever the failure
            ok = False
        checks[name] = "ok" if ok else "unavailable"
    healthy = all(value == "ok" for value in checks.values())
    return JSONResponse(
        {"status": "ok" if healthy else "degraded", "checks": checks},
        status_code=200 if healthy else 503,
    )


@router.get("/metrics", include_in_schema=False)
async def metrics_endpoint(request: Request, container: ContainerDep) -> PlainTextResponse:
    settings = container.settings
    if not settings.metrics_enabled:
        raise NotFound
    if settings.metrics_token is not None:
        header = request.headers.get("authorization", "")
        scheme, _, token = header.partition(" ")
        expected = settings.metrics_token.get_secret_value()
        if scheme.lower() != "bearer" or not hmac.compare_digest(token.encode(), expected.encode()):
            raise AuthenticationFailed
    return PlainTextResponse(render_metrics(), media_type=CONTENT_TYPE_LATEST)
