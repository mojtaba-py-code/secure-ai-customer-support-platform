# syntax=docker/dockerfile:1.7
#
# AegisSupport AI - production image.
#   * multi-stage: build tools and caches never reach the runtime image
#   * dependencies installed from the lock file (reproducible, hash-checked by uv)
#   * base images and the uv binary pinned by digest (Dependabot proposes updates)
#   * runs as an unprivileged user; works with a read-only root filesystem
#   * no shell tricks, no secrets baked in: configuration comes from the environment at runtime

FROM ghcr.io/astral-sh/uv:0.12.23@sha256:61d393e44e249f2e4b526b6c7ddcecce245946826e608e11c93ad4f5bba55b21 AS uv

FROM python:3.12-slim-bookworm@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3 AS build
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.12-slim-bookworm@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3 AS runtime
# `apt-get upgrade` applies the Debian security fixes published since the pinned base image was
# built (CI never restores this stage from its cache, so every build gets them). Nothing is
# installed on top of the base image.
RUN set -eu; \
    apt-get update; \
    apt-get upgrade -y --no-install-recommends; \
    rm -rf /var/lib/apt/lists/*; \
    groupadd --system --gid 10001 aegis; \
    useradd --system --uid 10001 --gid aegis --home-dir /app --no-create-home --shell /usr/sbin/nologin aegis
WORKDIR /app
COPY --from=build --chown=root:root /app/.venv /app/.venv
COPY --chown=root:root migrations ./migrations
COPY --chown=root:root alembic.ini ./
COPY --chown=root:root data ./data
RUN mkdir -p /app/var && chown aegis:aegis /app/var
ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AEGIS_LOG_JSON=true
USER aegis:aegis
EXPOSE 8000
# Probes /health/live with a Host header taken from AEGIS_ALLOWED_HOSTS (TrustedHost would reject
# "127.0.0.1" in production). The worker service overrides this with `aegis healthcheck --worker`.
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD ["aegis", "healthcheck"]
# Proxy headers are handled by the application (AEGIS_TRUSTED_PROXIES), not by uvicorn.
CMD ["uvicorn", "--factory", "aegis.main:create_app", "--host", "0.0.0.0", "--port", "8000", \
     "--no-server-header", "--no-access-log", "--no-proxy-headers", "--timeout-graceful-shutdown", "20"]
