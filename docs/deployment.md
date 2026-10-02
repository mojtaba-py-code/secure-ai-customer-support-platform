# Deployment

> **Status:** CI (`.github/workflows/ci.yml`, job "Container") builds the image on every change,
> checks it against an image policy, scans it with Trivy, and starts the full Compose stack from
> it - readiness, migration, seed and the end-to-end demo. The security properties of the
> container and Compose files are also unit-tested in `tests/integration/test_deployment.py`.

## Components to run

| Process | Command | Replicas | Needs |
|---|---|---|---|
| Migrations (one-off, before each release) | `aegis migrate` | 1 | the schema-owner database URL (`AEGIS_MIGRATION_DATABASE_URL`) |
| API | `uvicorn --factory aegis.main:create_app ...` (the image's default command) | 1..n | PostgreSQL (runtime role), Redis, Qdrant, provider keys |
| Worker | `aegis worker` | 1..n | same as the API |
| Demo data (optional, never in production) | `aegis seed` | - | refused when `AEGIS_ENV=production` |

## Docker Compose (single host)

```bash
uv run aegis init-env --docker        # writes .env with fresh secrets (owner-only permissions)
docker compose up -d --build          # postgres, redis, qdrant -> migrate -> api + worker
docker compose ps                     # api and worker become "healthy"
curl -s http://127.0.0.1:8000/health/ready
docker compose --profile demo run --rm seed   # optional fictional data (not in production)
docker compose logs -f api worker
```

What the stack does for you:

- **Networks**: `backend` is internal (no route out); only the API also joins `frontend` and is
  published on `127.0.0.1:8000`.
- **Least-privilege configuration**: no `env_file`; every container gets exactly the variables it
  needs. The migration job receives only the schema-owner URL; the API and worker receive the
  runtime role's URL and never see `POSTGRES_PASSWORD` or `AEGIS_DB_OWNER_PASSWORD`.
- **PostgreSQL**: `docker/postgres/init/01-roles.sh` creates `aegis_owner` (owns the database, no
  superuser) and `aegis_app` (runtime DML only) on first start; migration 0002 applies the grants
  and the audit trigger.
- **Redis**: the default user is disabled, the `aegis` user is confined to `aegis:*` keys without
  dangerous commands, memory is capped, nothing is persisted; the container runs as the `redis`
  user with no capabilities and a read-only root file system.
- **Qdrant**: API key required, telemetry off, unprivileged image, no capabilities.
- **Application containers**: non-root (uid 10001), read-only root file system with a small
  `tmpfs` for `/tmp`, all capabilities dropped, `no-new-privileges`, PID limit, health checks
  (`aegis healthcheck` for the API; `aegis healthcheck --worker` reads the worker's heartbeat file).

To use Claude, add `AEGIS_LLM_PROVIDER=anthropic` and `AEGIS_ANTHROPIC_API_KEY` to `.env`; other
optional settings forwarded by the Compose file are listed in `docker-compose.yml` (anything else
can be added to the `x-app-env` block).

## Production checklist

Work through this list before exposing a deployment to real customers.

**Configuration**

1. `AEGIS_ENV=production` - the process then refuses to start with SQLite, without Redis, with
   the embedded vector index, wildcard hosts or CORS, the development mailbox, metrics without a
   token, HSTS off, DEBUG or non-JSON logging, optional staff two-factor authentication, the
   simulated payment provider, or a placeholder JWT secret.
2. `AEGIS_ALLOWED_HOSTS` - the public host names only.
3. `AEGIS_CORS_ORIGINS` - the HTTPS origins of your web front end, or empty.
4. `AEGIS_TRUSTED_PROXIES` - exactly the address(es) your reverse proxy connects from (see below);
   otherwise per-client rate limits see only the proxy.
5. `AEGIS_HSTS_ENABLED=true` and serve only over TLS.
6. `AEGIS_EMAIL_BACKEND=smtp` with a relay that supports STARTTLS; set `AEGIS_PASSWORD_RESET_URL`
   to your front end's reset page.
7. Model limits that fit your budget: `AEGIS_LLM_USER_DAILY_TOKEN_BUDGET`,
   `AEGIS_LLM_GLOBAL_DAILY_COST_LIMIT_USD`, `AEGIS_RL_LLM_PER_USER_PER_MINUTE/DAY`.
8. `AEGIS_API_DOCS_ENABLED` stays unset (off in production) unless you need the OpenAPI UI.
9. `AEGIS_MFA_REQUIRED_FOR_STAFF=true`, and every staff member enrols an authenticator app before
   their first shift (unenrolled staff can sign in but hold no permissions).
10. Payments: `AEGIS_PAYMENT_PROVIDER=stripe` with a restricted key limited to refunds, and a
    Stripe webhook endpoint `https://<host>/api/v1/webhooks/stripe` for `refund.*` events whose
    signing secret is `AEGIS_STRIPE_WEBHOOK_SECRET`.
11. Privacy: choose `AEGIS_CONVERSATION_RETENTION_DAYS` with your legal team and assign the
    erasure procedure (see [operations.md](operations.md#routine-tasks)).

**Secrets and keys**

12. Secrets come from a secret manager - environment variables injected at start-up or files in
   `AEGIS_SECRETS_DIR` - never from a committed file or a baked image layer.
13. Separate values per environment; generate them with `aegis generate-secrets`.
14. Store the Fernet keys (`AEGIS_FIELD_ENCRYPTION_KEYS`) with your backups' recovery material:
    without them, encrypted columns cannot be read.

**Infrastructure**

15. PostgreSQL: the three-role layout (bootstrap superuser unused by the application; owner only
    for migrations; runtime role for the app), TLS between the application and the database when
    they are on different hosts, backups with tested restores.
16. Redis: ACL user restricted to the key prefix, no dangerous commands, `maxmemory` with
    `volatile-lru`, TLS across hosts (`rediss://`), not reachable from outside.
17. Qdrant: API key, TLS across hosts (`https://`), not reachable from outside.
18. Only the reverse proxy is reachable from the Internet; the data services sit on a private
    network.
19. Log shipping of the JSON logs, and alerts on the metrics listed in
    [operations.md](operations.md#alerts).

**Release process**

20. Build the image from the lock file, scan it with your container scanner, run
    `uv run pip-audit` and the full test suite (also against PostgreSQL) in CI.
21. Run `aegis migrate` as a one-off job with the owner credentials before rolling out the new
    API and worker.
22. Never run `aegis seed` in production (it refuses to).

## Reverse proxy

Terminate TLS in front of the API and forward the client address. Example (nginx):

```nginx
server {
    listen 443 ssl http2;
    server_name support.example.com;
    ssl_certificate     /etc/ssl/certs/support.example.com.pem;
    ssl_certificate_key /etc/ssl/private/support.example.com.key;

    client_max_body_size 2m;            # uploads are limited to 1 MiB by the application

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Request-ID $request_id;
        proxy_read_timeout 90s;         # an assistant turn may take up to AEGIS_AGENT_TURN_TIMEOUT_SECONDS
    }
}
```

Set `AEGIS_TRUSTED_PROXIES` to the address the API *sees* for the proxy. With Docker port
publishing that is usually the bridge network's gateway rather than `127.0.0.1` - check the
`client_ip` field of the API's access log, or run the proxy as a container on the `frontend`
network and trust that container's address. The application takes the right-most address in
`X-Forwarded-For` that is not a trusted proxy, so clients cannot spoof it.

The application sets HSTS, CSP and the other security headers itself; the proxy should not
remove them.

## Secret management and rotation

| Secret | Rotation |
|---|---|
| `AEGIS_JWT_SECRET` | Replace and restart. Existing access tokens become invalid (clients refresh them - refresh tokens are opaque and unaffected). The prompt canary is derived from it and changes too. |
| `AEGIS_FIELD_ENCRYPTION_KEYS` | Prepend a new key (`new,old`), restart, run `aegis rotate-encryption`, then remove the old key and restart again. |
| `AEGIS_METRICS_TOKEN` | Replace in the application and in the Prometheus scrape configuration. |
| Database passwords | `ALTER ROLE ... PASSWORD ...` as the superuser, update the secret, restart the consumers. |
| `REDIS_PASSWORD` | Update the ACL user (`ACL SETUSER`) or restart Redis with the new value, update the secret, restart the application. |
| `QDRANT_API_KEY` | Restart Qdrant and the application with the new key. |
| Provider API keys (Claude, Voyage AI, Stripe) | Create the new key in the provider console, update the secret, restart, revoke the old key. |
| `AEGIS_STRIPE_WEBHOOK_SECRET` | Roll the endpoint secret in Stripe (it signs with both for a while - the verifier accepts either), update the setting, restart. |

With files in `AEGIS_SECRETS_DIR` (for example a Kubernetes secret mounted as a volume), each
variable is one file named after it (`AEGIS_JWT_SECRET`, `AEGIS_DATABASE_URL`, ...). Environment
variables win over `.env`, which wins over secret files.

## Scaling

- **API**: stateless - add replicas behind the proxy. Size the database pool so that
  `(AEGIS_DATABASE_POOL_SIZE + AEGIS_DATABASE_MAX_OVERFLOW) x replicas` stays below PostgreSQL's
  `max_connections` (or put PgBouncer in transaction mode in front).
- **Worker**: several replicas are safe (atomic document claims); one is usually enough.
- **Redis** and **Qdrant** are shared by all replicas; the embedded modes are single-process and
  refused in production.
- **Model throughput**: the per-user limits and budgets bound the spend; the circuit breaker and
  offline fallback keep the service answering when the provider throttles.

## Without Docker

Install with `uv sync --frozen --no-dev` (or build a wheel), provide the environment through your
process manager or secret store, run `aegis migrate` with the owner URL, then run the API with
`uvicorn --factory aegis.main:create_app --host 127.0.0.1 --port 8000 --no-server-header
--no-access-log --no-proxy-headers` and the worker with `aegis worker` (for example as two
systemd services with `NoNewPrivileges=yes`, `ProtectSystem=strict` and a dedicated user).

## Upgrading

1. Read the release notes for migrations.
2. Back up the database.
3. Run `aegis migrate` (owner credentials).
4. Roll out the API and the worker.
5. Watch `/health/ready`, error rates and the security metrics.

Migrations are written to be applied before the new code starts; destructive schema changes
(dropping columns) are split across two releases (expand, then contract).
