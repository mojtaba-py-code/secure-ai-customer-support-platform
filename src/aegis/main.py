"""ASGI application factory.

Run with ``uvicorn --factory aegis.main:create_app`` (or ``aegis serve``). Middleware order,
outermost first:

    RequestContext (request id, client ip, access log, metrics)
      -> SecurityHeaders -> ErrorBoundary (generic 500s) -> TrustedHost -> CORS
      -> BodySizeLimit -> ContentType -> FastAPI (exception handlers -> routes)
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from aegis import __version__
from aegis.api.errors import register_exception_handlers
from aegis.api.health import router as health_router
from aegis.api.router import UPLOAD_PATHS, api_router
from aegis.bootstrap import AppContainer
from aegis.core.config import Settings, load_settings
from aegis.middleware.errors import ErrorBoundaryMiddleware
from aegis.middleware.limits import BodySizeLimitMiddleware, ContentTypeMiddleware
from aegis.middleware.request_context import RequestContextMiddleware
from aegis.middleware.security_headers import SecurityHeadersMiddleware
from aegis.observability.logging import configure_logging

MULTIPART_OVERHEAD = 64 * 1024


def create_app(
    settings: Settings | None = None, *, container: AppContainer | None = None
) -> FastAPI:
    settings = settings or load_settings()
    configure_logging(level=settings.log_level, json_output=settings.log_json)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        owned = container is None
        active = container or AppContainer(settings)
        if owned:
            await active.startup()
        app.state.container = active
        try:
            yield
        finally:
            if owned:
                await active.close()

    docs = settings.docs_enabled
    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        description="Secure LLM-powered customer support platform.",
        docs_url="/docs" if docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if docs else None,
        lifespan=lifespan,
    )
    if container is not None:
        app.state.container = container
    register_exception_handlers(app)
    app.include_router(health_router)
    app.include_router(api_router)

    # Starlette wraps in reverse order of registration: the last added is the outermost.
    app.add_middleware(ContentTypeMiddleware, multipart_paths=UPLOAD_PATHS)
    app.add_middleware(
        BodySizeLimitMiddleware,
        default_limit=settings.max_request_body_bytes,
        upload_limit=settings.max_upload_bytes + MULTIPART_OVERHEAD,
        upload_paths=UPLOAD_PATHS,
    )
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=False,
            allow_methods=["GET", "POST", "PATCH", "DELETE"],
            allow_headers=["Authorization", "Content-Type", "Idempotency-Key", "X-Request-ID"],
            expose_headers=["X-Request-ID", "Retry-After"],
            max_age=600,
        )
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
    app.add_middleware(ErrorBoundaryMiddleware)
    app.add_middleware(SecurityHeadersMiddleware, hsts=settings.hsts_enabled)
    app.add_middleware(RequestContextMiddleware, trusted_proxies=settings.trusted_proxies)
    return app
