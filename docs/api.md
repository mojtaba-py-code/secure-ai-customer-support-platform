# API guide

Conventions shared by every endpoint. The endpoint list, with the permission and rate limits of
each route, is generated from the code in [api-reference.md](api-reference.md); request and
response schemas are served at `/docs` (OpenAPI) when `AEGIS_API_DOCS_ENABLED` is on - by default
everywhere except production.

## Basics

| Topic | Convention |
|---|---|
| Base path | `/api/v1`. Breaking changes get a new version prefix; additive changes (new optional fields, new endpoints) do not. Health probes live outside the versioned tree (`/health/live`, `/health/ready`). |
| Format | JSON in, JSON out. Requests with a body must be `Content-Type: application/json` (`multipart/form-data` only on the upload route), otherwise **415**. Unknown fields in a request body are rejected (**422**). |
| Sizes | JSON bodies up to `AEGIS_MAX_REQUEST_BODY_BYTES` (64 KiB by default), uploads up to `AEGIS_MAX_UPLOAD_BYTES` (1 MiB); larger requests get **413** before the body is read. Messages are limited to 4,000 characters. |
| Hosts | The `Host` header must be one of `AEGIS_ALLOWED_HOSTS`, otherwise a plain-text **400** `Invalid host header` (answered by the host filter before any application code). |
| Times | ISO 8601 in UTC (`2026-09-30T12:00:00Z`). |
| Money | Integer minor units plus an ISO currency: `"total_cents": 49800, "currency": "USD"`. |
| Identifiers | UUIDs for records; human-readable references for customers: `ORD-100231`, `TCK-40718263`, `RFD-12281238`. |
| Request id | Every response carries `X-Request-ID`. A client may send its own (8-64 characters of `A-Z a-z 0-9 . _ -`); anything else is replaced. Quote it when reporting a problem. |
| CORS | Off unless `AEGIS_CORS_ORIGINS` lists origins; credentials are never allowed (tokens travel in the `Authorization` header, not in cookies). |

## Authentication

```text
POST /api/v1/auth/login      {"email": "...", "password": "..."}
  -> {"access_token": "<JWT>", "token_type": "bearer", "expires_in": 900,
      "access_expires_at": "...", "refresh_token": "<opaque>", "refresh_expires_at": "..."}

Authorization: Bearer <access_token>             on every other call

POST /api/v1/auth/refresh    {"refresh_token": "..."}   -> a new pair; the old refresh token is spent
POST /api/v1/auth/logout                                -> ends this session
POST /api/v1/auth/logout-all                            -> ends every session of the user
GET  /api/v1/auth/me                                    -> user id, role, permissions
```

- **Access tokens** are HS256 JWTs valid for `AEGIS_ACCESS_TOKEN_TTL_SECONDS` (15 minutes). A
  valid signature is not enough: the session and the user are loaded from the database on every
  request, so logout, password change, deactivation and role changes take effect immediately.
- **Refresh tokens** are opaque, single use and rotate on every refresh. Presenting a spent
  refresh token is treated as theft: the whole session is revoked. Sessions also have an
  absolute lifetime (`AEGIS_SESSION_MAX_AGE_SECONDS`).
- **Failed logins** always return the same `401` ("Invalid email or password.") whether the
  account exists, the password is wrong, or the account is locked or disabled. After
  `AEGIS_LOGIN_MAX_FAILED_ATTEMPTS` failures the account is locked for
  `AEGIS_LOGIN_LOCKOUT_SECONDS`.
- **Password reset**: `POST /auth/password-reset/request` always answers `202` with the same
  message. If the account exists, an e-mail with a single-use link is sent; the token travels in
  the URL *fragment* (`https://.../reset-password#token=...`) so it never reaches server logs or
  `Referer` headers. `POST /auth/password-reset/confirm` sets the new password and revokes every
  session.
- **Password policy**: at least `AEGIS_PASSWORD_MIN_LENGTH` characters, not a common password,
  not derived from the e-mail address (NIST SP 800-63B style: length over composition rules).

### Two-factor authentication (TOTP)

```text
POST /api/v1/auth/mfa/setup     {"password": "..."}   -> {"secret": "...", "otpauth_uri": "otpauth://totp/..."}
POST /api/v1/auth/mfa/enable    {"code": "123456"}    -> {"recovery_codes": ["k3vq-8mzt-r2hx-9pwc", ...]}
                                                          every session ends: sign in again
POST /api/v1/auth/login         {"email", "password"} -> {"mfa_required": true, "mfa_token": "...", "expires_in": 300}
POST /api/v1/auth/mfa/verify    {"mfa_token", "code"} -> the usual token pair
GET  /api/v1/auth/mfa                                 -> {"enabled", "enrollment_required", "recovery_codes_remaining"}
POST /api/v1/auth/mfa/recovery-codes  {"code"}        -> a new set (the old codes stop working)
POST /api/v1/auth/mfa/disable   {"password", "code"}  -> 204 (not for staff while it is required)
```

- The secret works with any authenticator app (show `otpauth_uri` as a QR code). It and the
  recovery codes are shown exactly once; the server stores the secret encrypted and the recovery
  codes as SHA-256 digests.
- `code` is the 6-digit code or one of the recovery codes (single use). A code is valid for its
  30-second step and one step either side, and never twice.
- The `mfa_token` is single use, expires after `AEGIS_MFA_CHALLENGE_TTL_SECONDS` and dies after
  five wrong codes; wrong codes also count towards the account lockout.
- With `AEGIS_MFA_REQUIRED_FOR_STAFF=true` (mandatory in production) a staff member without a
  second factor can sign in, but `/auth/me` reports `mfa_enrollment_required: true`, the
  permission list is empty, and every staff endpoint answers 403 until enrolment is finished.
- A lost device: an administrator calls `POST /api/v1/admin/users/{id}/reset-mfa` (never for
  their own account); the user signs in with the password and enrols again.

## Authorisation

Four roles: `customer`, `support_agent`, `support_manager`, `admin`, holding 33 fine-grained
permissions (the matrix is in [api-reference.md](api-reference.md#role-permissions-rbac-matrix)).
Two checks run for every protected operation:

1. **capability** - the role must hold the permission (`403` otherwise);
2. **ownership** - customers only ever see their own records. Ownership is part of the SQL query,
   and a record that exists but belongs to someone else is answered with **404**, exactly like a
   record that does not exist, so identifiers cannot be enumerated.

Staff roles deliberately lack the customer-only permissions (starting a customer conversation,
confirming a customer's refund or cancellation).

## Errors

Every error is an [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) problem document with media
type `application/problem+json`:

```json
{
  "type": "about:blank",
  "title": "Not Found",
  "status": 404,
  "detail": "The requested resource was not found.",
  "code": "not_found",
  "request_id": "5992cc8f9be04d14856ca72f3df598b9"
}
```

`detail` is always written for end users; stack traces, SQL, file paths, hostnames and exception
messages never appear in responses (unexpected errors become a generic `500 internal_error`).
Some errors add a `details` object with machine-readable, public data - for example
`{"reasons": ["already_shipped"]}` when an order can no longer be cancelled, the failed password
rules, or `{"provider_code": "charge_already_refunded"}` when the payment provider refuses a refund.
Validation errors (`422 validation_error`) add an `errors` list with the location, a short message
and the error type of each problem - but never the submitted value, so a mistyped password cannot
be echoed back.

| Status | `code` examples | Meaning |
|---|---|---|
| 400 | `http_400` | Malformed request |
| 401 | `authentication_failed` | Missing, invalid or expired token (`WWW-Authenticate: Bearer`) |
| 403 | `permission_denied` | The role lacks the permission |
| 404 | `not_found` | Not found - or not yours |
| 409 | `conflict`, `resource_busy`, `payment_rejected` | State conflict (e.g. the order has shipped), the conversation is already processing a message, or the payment provider refused a refund |
| 413 | `payload_too_large` | Body or upload too large |
| 415 | `unsupported_media_type` | Wrong `Content-Type` or file type |
| 422 | `validation_error` | Invalid input |
| 429 | `rate_limited`, `budget_exceeded` | Too many requests (`Retry-After` header), or the model budget is exhausted |
| 500 | `internal_error` | Unexpected error (logged with the request id) |
| 503 | `service_unavailable`, `dependency_unavailable` | A dependency is down; retry later |

## Pagination

List endpoints take `limit` (1-100, default 20 or 50) and `offset` (0-10,000) and return:

```json
{"items": [...], "limit": 20, "offset": 0}
```

The offset cap keeps deep pagination (and its database cost) bounded; filter instead of paging
far. Conversation messages page backwards with `?before=<sequence>`.

## Idempotency

`POST /conversations/{id}/messages` and `POST /support/tickets` accept an `Idempotency-Key`
header (8-120 characters of letters, digits, `-` and `_`; a UUID is ideal):

| Situation | Result |
|---|---|
| Same key, same body, first request finished | The original result is returned; nothing runs twice (no second model call, no second ticket) |
| Same key, different body | **422** - a client bug that must not be silently "fixed" |
| Same key while the first request is still running | **409** - retry a moment later |
| The first request failed | The key is released; the retry runs normally |

Keys are scoped per user and per endpoint (per conversation for messages) and kept for `AEGIS_IDEMPOTENCY_TTL_SECONDS` (24 hours).
Confirming a pending action is naturally idempotent: the action can move from `pending` to
`executing` only once.

## Rate limits

Limits are sliding windows kept in Redis and shared by all replicas: every `/api/v1` request is
counted per client IP *before* authentication (so floods with invalid tokens are throttled too),
authenticated calls per user, and stricter classes apply to login (per IP and per account),
refresh, password reset, model calls, uploads and administration - see `AEGIS_RL_*` in
[configuration.md](configuration.md) and the per-route list in
[api-reference.md](api-reference.md). Behind a reverse proxy, set `AEGIS_TRUSTED_PROXIES`, or
every client shares the proxy's address.
A rejected request gets **429** with `Retry-After` (seconds). Rejected requests still count, so a
client that keeps hammering stays blocked. If Redis is unreachable, the limits are enforced per
process instead - they never switch off.

## Talking to the assistant

```text
POST /api/v1/conversations                         {"subject": "optional"}          -> 201
POST /api/v1/conversations/{id}/messages           {"content": "Where is ORD-100232?"}
  -> {
       "conversation_id": "...", "conversation_status": "active",
       "customer_message": {...},
       "reply": {"content": "...", "citations": [{"index": 1, "title": "...", "section": "..."}], ...},
       "intent": "order_tracking", "escalated": false, "ticket_number": null,
       "pending_actions": [],
       "notice": null
     }
```

- The stored customer message is the redacted storage view: card numbers and similar data the
  customer typed are removed (and the reply reminds them not to share such data).
- `pending_actions` lists refund requests or cancellations the assistant prepared. Nothing has
  happened yet: confirm with `POST .../actions/{action_id}/confirm` or decline with
  `.../decline`. Actions expire after `AEGIS_AGENT_ACTION_TTL_SECONDS`.
- `escalated: true` means a human took over (`ticket_number` is set). While a specialist handles
  the conversation, `reply` is `null` and `notice` explains that the specialist will answer; the
  specialist's messages appear in `GET .../messages` with `sender_type: "agent"`.
- Only one message per conversation is processed at a time; a concurrent one gets **409
  resource_busy**.

## Privacy requests

```text
GET  /api/v1/privacy/export             -> everything stored about the signed-in customer (JSON download)
POST /api/v1/privacy/erasure-request    -> 202 {"ticket_number": "TCK-...", ...}
POST /api/v1/admin/customers/{id}/erase {"customer_number": "CUS-10006"}   (administrators)
```

- The export contains the customer profile, the login(s), orders with items and payments,
  refunds, conversations with their messages, and tickets - no internal metadata. It is limited to
  `AEGIS_RL_PRIVACY_EXPORT_PER_DAY` downloads per day.
- An erasure request opens (at most one per day) a `privacy` ticket for the support team. After
  verifying the request, an administrator runs the erasure, typing the customer number as
  confirmation. It is refused with `409` and `details.reasons` while orders, refunds or confirmed
  actions are still in progress.
- Erasure is irreversible: contact data and every free text (messages, summaries, tickets, notes)
  are replaced, the login is disabled and renamed, sessions and second factors are removed.
  Orders, payments and refunds stay for accounting, without anything pointing to the person.

## Payment webhooks

`POST /api/v1/webhooks/stripe` receives refund outcomes from Stripe when
`AEGIS_PAYMENT_PROVIDER=stripe` (otherwise 404). The body is accepted only with a valid
`Stripe-Signature` (HMAC-SHA256 over the raw body with `AEGIS_STRIPE_WEBHOOK_SECRET`, timestamp at
most five minutes old); anything else gets `400` and a security event. Only `refund.*` events are
processed, idempotently: a refund that is `processing` becomes `completed` or `failed`, repeated
or late events change nothing. The answer is `{"received": true, "result": "completed" |
"failed" | "unchanged" | "ignored" | "unknown_refund"}`.
