# Operations: monitoring, logging, troubleshooting

## Health endpoints

| Endpoint | Meaning | Use for |
|---|---|---|
| `GET /health/live` | The process serves HTTP | Liveness probe (restart when failing) |
| `GET /health/ready` | Database, cache and vector store answer within 3 s each: `{"status": "ok", "checks": {"database": "ok", "cache": "ok", "vector_store": "ok"}}`, otherwise HTTP 503 with `"status": "degraded"` and `unavailable` for the failing component - never hostnames or error text | Readiness probe (take out of the load balancer) |
| `aegis healthcheck` | Container probe: calls `/health/live` with a `Host` header from `AEGIS_ALLOWED_HOSTS` | Docker `HEALTHCHECK` of the API |
| `aegis healthcheck --worker` | The worker touched `AEGIS_WORKER_HEARTBEAT_FILE` within `--max-age` seconds (default 300) | Health check of the worker |

## Metrics

Prometheus text format at `GET /metrics`, protected by `Authorization: Bearer <AEGIS_METRICS_TOKEN>`
(mandatory in production). Label values come from small closed sets (route templates, tool names,
intents, outcomes), so crafted input cannot explode cardinality.

| Metric | Labels | What to watch |
|---|---|---|
| `aegis_http_requests_total` | method, route, status | error rates (5xx), 401/403/429 spikes |
| `aegis_http_request_duration_seconds` | method, route | latency of the message endpoint in particular |
| `aegis_llm_requests_total` | provider, task, outcome | refusals, errors, timeouts, `offline` share |
| `aegis_llm_latency_seconds` | provider, task | provider slowness |
| `aegis_llm_tokens_total` | provider, model, kind (input, output, cache_read, cache_write) | consumption, cache effectiveness |
| `aegis_llm_cost_usd_total` | model | estimated spend |
| `aegis_circuit_open` | circuit | 1 while the model circuit is open or half-open |
| `aegis_agent_turns_total` | intent, outcome (answered, clarify, refused, escalated, fallback, failed) | quality: fallback and failure share |
| `aegis_tool_calls_total` | tool, outcome | denied and failed tool calls |
| `aegis_escalations_total` | reason | human workload, security escalations |
| `aegis_output_guard_violations_total` | kind | leaks blocked, links/PII removed, ungrounded facts |
| `aegis_rag_retrievals_total` | outcome (hit, empty, error) | knowledge-base coverage and availability |
| `aegis_rag_chunks_returned` | - | retrieval depth |
| `aegis_rate_limited_total` | policy | abuse, or limits set too low |
| `aegis_security_events_total` | event | see below |

Security events (`aegis_security_events_total{event=...}`): `login_failed`, `account_locked`,
`mfa_failed`, `mfa_recovery_code_used`, `refresh_token_reuse`, `authorization_denied`,
`webhook_signature_invalid`, `prompt_injection_suspected`,
`prompt_leak_blocked`, `tool_not_allowed`, `tool_invalid_arguments`, `tool_permission_denied`,
`kb_document_quarantined`, `kb_chunk_dropped`, `rag_chunk_injection_blocked`,
`rag_visibility_violation`, `rate_limit_degraded`.

## Alerts

Suggested starting points (tune the thresholds to your traffic):

| Alert | Expression (PromQL) | Why |
|---|---|---|
| Visibility violation | `increase(aegis_security_events_total{event="rag_visibility_violation"}[5m]) > 0` | Should never happen - a filter bug; page someone |
| Refresh-token reuse | `increase(aegis_security_events_total{event="refresh_token_reuse"}[15m]) > 0` | A stolen token was used |
| Forged webhooks | `increase(aegis_security_events_total{event="webhook_signature_invalid"}[15m]) > 0` | Someone is sending fake payment events - or the webhook secret was rotated on one side only |
| Second-factor guessing | `increase(aegis_security_events_total{event="mfa_failed"}[15m]) > 20` | Someone holds passwords and is trying codes |
| Prompt leak blocked | `increase(aegis_security_events_total{event="prompt_leak_blocked"}[1h]) > 3` | Someone is probing the assistant |
| Injection wave | `increase(aegis_security_events_total{event="prompt_injection_suspected"}[15m]) > 20` | Coordinated attack |
| Credential stuffing | `increase(aegis_security_events_total{event="login_failed"}[5m]) > 100` | Brute force from many sources |
| Rate limiter degraded | `increase(aegis_security_events_total{event="rate_limit_degraded"}[5m]) > 0` | Redis unreachable; limits are per process |
| Model circuit open | `max(aegis_circuit_open) == 1` for 5 minutes | Provider outage; answers are degraded |
| Spend | `increase(aegis_llm_cost_usd_total[1h])` above your budget share | Cost anomaly |
| Assistant failures | share of `outcome="failed"` or `"fallback"` in `aegis_agent_turns_total` above 10 % | Quality regression |
| Errors | `sum(rate(aegis_http_requests_total{status=~"5.."}[5m]))` above baseline | Bugs or dependency trouble |

## Logs

One JSON object per line on stdout (`AEGIS_LOG_JSON=true`, required in production):

```json
{"ts": "2026-09-30T14:00:36.512+00:00", "level": "INFO", "logger": "aegis.access", "msg": "request",
 "request_id": "5992cc8f...", "user_id": "c3b1...", "client_ip": "198.51.100.7",
 "event": "http.request", "method": "POST", "route": "/api/v1/conversations/{conversation_id}/messages",
 "status": 200, "duration_ms": 812.4}
```

- Every line carries the request id, the user id and the client address when known; the request
  id is also returned to the client as `X-Request-ID`, so a support case can be traced end to end.
- Logs contain events and identifiers - **never** message text, passwords, tokens, addresses or
  card numbers. A redaction filter is the safety net: sensitive field names are replaced wholesale
  and every value is scrubbed for secrets and personal data. Exceptions are logged as type plus a
  scrubbed message, without tracebacks.
- Useful `event` values: `http.request`, `http.error`, `http.unhandled_error`, `audit`,
  `llm.degraded`, `circuit.state`, `classify.fallback`, `classify.malformed`, `tool.call`,
  `tool.crash`, `rag.chunk_blocked`, `rag.visibility_violation`, `rate_limit.degraded`,
  `kb.index_deferred`, `kb.index_failed`, `kb.reconciled`, `agent.turn_failed`,
  `memory.summary_failed`, `email.sent`, `email.failed`, `worker.iteration`, `worker.error`.

## Audit trail

`audit_events` records who did what, when, from where and with which outcome (`success`,
`failure`, `denied`, `error`). It is append-only on PostgreSQL and readable by administrators at
`GET /api/v1/admin/audit-events` (filters: `action` prefix such as `auth.`, `actor_user_id`,
`outcome`, `since`). Recorded actions
include:

- authentication: `auth.login` (success - with the second-factor method - and failure with a
  reason code), `auth.mfa_challenge`, `auth.mfa_verify`, `auth.refresh`,
  `auth.refresh_reuse_detected`, `auth.logout`, `auth.logout_all`, `auth.password_change`,
  `auth.password_reset_request`, `auth.password_reset`, `auth.mfa_setup`, `auth.mfa_enable`,
  `auth.mfa_disable`, `auth.mfa_recovery_codes`;
- administration: `admin.user_create`, `admin.user_update`, `admin.user_unlock`,
  `admin.user_revoke_sessions`, `admin.user_reset_mfa`, `kb.upload`, `kb.approve_quarantined`,
  `kb.indexed`, `kb.archive`;
- privacy: `privacy.export`, `privacy.erasure_request`, `privacy.erase`;
- payments: `payment.webhook` (rejected signatures), `refund.provider_update`;
- the assistant: `agent.turn`, `agent.injection_suspected`, `agent.tool_denied`,
  `action.propose`, `action.confirm`, `action.decline`;
- support work: `handoff.escalate`, `handoff.assign`, `handoff.reply`, `handoff.resolve`,
  `ticket.create`, `ticket.update`, `refund.decide`, `conversation.close`.

Audit details are scrubbed and size-capped; they never contain message text or submitted
passwords. Each event is written in its own transaction, so failed operations still leave their
record.

## Model usage and cost

`GET /api/v1/admin/llm-usage?days=7` (permission `usage:read`, up to 90 days) summarises tokens
and estimated cost per model and task. Budgets are enforced in Redis per day (UTC); raise or lower
them with `AEGIS_LLM_USER_DAILY_TOKEN_BUDGET` and `AEGIS_LLM_GLOBAL_DAILY_COST_LIMIT_USD`. When a
budget is exhausted the assistant keeps answering through the offline model (flagged
`degraded`).

## Routine tasks

| Task | How |
|---|---|
| Unlock a customer or staff account | `POST /api/v1/admin/users/{id}/unlock` |
| Reset a lost second factor | Verify the person out of band, then `POST /api/v1/admin/users/{id}/reset-mfa`; the user signs in with the password and enrols again |
| Complete an erasure request | Find the `privacy` ticket, verify the requester, then `POST /api/v1/admin/customers/{id}/erase` with the customer number; if it answers `409`, `details.reasons` lists the work still in progress |
| Set a retention period | `AEGIS_CONVERSATION_RETENTION_DAYS=<days>`; the worker applies it every maintenance run |
| Connect Stripe | Create a restricted key (refunds only) and a webhook endpoint `https://<host>/api/v1/webhooks/stripe` for the `refund.*` events; put the key and the endpoint's signing secret into `AEGIS_STRIPE_API_KEY` / `AEGIS_STRIPE_WEBHOOK_SECRET`, set `AEGIS_PAYMENT_PROVIDER=stripe` |
| Sign a user out everywhere | `POST /api/v1/admin/users/{id}/revoke-sessions` (or deactivate with `PATCH`) |
| Create the first administrator | `aegis create-admin --email ...` (password prompted, or `AEGIS_BOOTSTRAP_ADMIN_PASSWORD`) |
| Review quarantined documents | `GET /api/v1/admin/knowledge-base/documents?status=quarantined`, then approve or delete |
| Re-index a document | `POST /api/v1/admin/knowledge-base/documents/{id}/reindex` |
| Rebuild the vector index | `aegis index-kb --rebuild` into an empty collection (see [rag.md](rag.md#embeddings)) |
| Rotate the encryption key | see [deployment.md](deployment.md#secret-management-and-rotation) |
| Validate a configuration | `aegis check-config` (prints a summary without secrets) |

## Troubleshooting

| Symptom | Likely cause | What to do |
|---|---|---|
| The process exits at start with `unsafe production configuration: ...` | A production rule is violated | The message lists every problem; fix the variables named there |
| `AEGIS_JWT_SECRET must be at least 32 characters` or a Fernet key error | Missing or weak secrets | `aegis generate-secrets` / `aegis init-env` |
| Every request gets `400 Invalid host header` | The `Host` is not in `AEGIS_ALLOWED_HOSTS` | Add the public host name (and check the proxy forwards `Host`) |
| All clients share one rate limit / audit IP | Requests arrive through a proxy that is not trusted | Set `AEGIS_TRUSTED_PROXIES` to the proxy's address as the API sees it |
| `429` with `Retry-After` | A rate limit was hit | Wait; if legitimate traffic is affected, raise the matching `AEGIS_RL_*` |
| A staff member gets `403` everywhere and `/auth/me` shows no permissions | Two-factor authentication is required and not set up yet | The user enrols (`/auth/mfa/setup` and `/auth/mfa/enable`), then signs in again |
| "The verification code is invalid or has expired" although the app shows a code | The device clock is off by more than 30 s, the code was already used, or the challenge expired or had five wrong tries | Fix the device time, wait for the next code, sign in again; use a recovery code if needed |
| Refunds stay `processing` | The Stripe webhook is not configured, points elsewhere, or its secret differs | Check `payment.webhook` audit events and `webhook_signature_invalid`; fix the endpoint or `AEGIS_STRIPE_WEBHOOK_SECRET` - Stripe retries delivery |
| Approval fails with `409 payment_rejected` | Stripe refused the refund (`details.provider_code`, e.g. `charge_already_refunded`) | Resolve it in the Stripe dashboard; the refund stays reviewable in the platform |
| `409 resource_busy` on messages | A message in the same conversation is still being processed | The client should wait for the previous reply |
| Replies are marked `degraded` | The model provider is unavailable, the circuit is open, or a budget is exhausted | Check `llm.degraded` logs (they state the reason), `aegis_circuit_open`, the provider status and the budgets |
| `llm.auth_failed` in the logs | Invalid or revoked `AEGIS_ANTHROPIC_API_KEY` | Replace the key |
| Uploaded documents stay `pending` | No worker running, or the embedding provider is failing | Start the worker (or upload with `?index_now=true`); check `kb.index_deferred` logs |
| A document is `quarantined` | Injection indicators in the content | Review its content; approve only if the text is legitimate |
| Start-up fails with `stores N-d vectors but the embedder produces M-d vectors` | The embedding dimensions changed | Index into a new collection (see [rag.md](rag.md#embeddings)) |
| `Storage folder ... is already accessed by another instance of Qdrant client` | Two processes opened the same embedded (directory) index | In development run only one process against `var/qdrant`, or use a Qdrant server |
| `aegis migrate` fails with `permission denied` or `must be owner` | Migrations run as the runtime role | Run them with `AEGIS_MIGRATION_DATABASE_URL` set to the owner role |
| `NOPERM` errors from Redis | The ACL user cannot access the key prefix | Keep `AEGIS_REDIS_KEY_PREFIX` (default `aegis`) in line with the ACL `~aegis:*` pattern |
| Readiness shows `cache: unavailable` | Redis is down or the password is wrong | The API still limits requests per process, but new messages fail with 503 until Redis is back |
| Password-reset e-mails do not arrive | SMTP settings, or `email_backend=disabled` | Check `email.failed` logs; in development they are written to `var/mailbox` |
