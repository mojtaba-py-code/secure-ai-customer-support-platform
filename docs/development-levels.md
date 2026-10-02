# How the system was built: 20 levels

The project was developed in the 20 levels of its brief. Each level below records the goal, what
was built (with the files), the concepts it relies on, common mistakes it avoids, how to verify
it, and the mini security review written at the end of the level. The final comprehensive review
is [security-audit.md](security-audit.md).

Run any level's verification from the project root after `uv sync`.

---

## Level 1 - Architecture and requirements

**Goal.** Decide what the system must do and which properties are non-negotiable before writing
code: the model is untrusted; authorisation, tool access and output safety live in code.

**Built.** The layered modular-monolith design, the trust boundaries, the agent pipeline and the
data-flow and threat model skeleton ([architecture.md](architecture.md), [threat-model.md](threat-model.md)).

**Concepts.** Trust boundaries; defence in depth; least privilege; "the model proposes, code
decides"; fail-closed defaults.

**Common mistakes avoided.** Designing the agent first and bolting security on later; letting
the model call the database or choose URLs; one monolithic prompt as the only control.

**Verify.** Read the diagrams; the layering is enforced from Level 2 on (`uv run lint-imports`).

```text
Security Review
Threats:              prompt injection, broken access control, data leakage, excessive agency, cost abuse
Attack Surface:       HTTP API, customer messages, uploaded documents, model output, provider calls
Current Protections:  none yet - design decisions only
Remaining Risks:      everything; the design must be carried into code
Recommended Improvements: make each design rule a test or a machine-checked contract
```

## Level 2 - Project structure and configuration

**Goal.** A professional skeleton: packaging, tooling, typed configuration and secrets handling.

**Built.** `pyproject.toml` (dependencies with bounds, ruff incl. security rules and banned APIs,
strict mypy, pytest, coverage gate, bandit, import-linter contracts), `uv.lock`,
`src/aegis/core/config.py` (typed `Settings`, `SecretStr`, production rules, secret files,
empty-means-unset), `src/aegis/cli.py` (`init-env`, `generate-secrets`, `check-config`),
`.env.example`, `.gitignore`, `.dockerignore`, `scripts/generate_docs.py`.

**Concepts.** Twelve-factor configuration; typed settings; secrets that cannot be printed;
refusing unsafe production configuration at start-up; architecture as a tested contract.

**Common mistakes avoided.** Hard-coded secrets or default secrets; `.env` committed; settings
read ad hoc all over the code; validation errors echoing secret values.

**Verify.** `uv run pytest tests/unit/test_config.py`, `uv run aegis check-config`, `uv run lint-imports`.

```text
Security Review
Threats:              leaked secrets, unsafe production defaults, weak keys
Attack Surface:       environment, .env files, logs, error messages
Current Protections:  SecretStr everywhere, strength checks, production refusal rules, generated
                      secrets written owner-only, secret files (AEGIS_SECRETS_DIR)
Remaining Risks:      secrets in the process environment are readable by anyone with host access
Recommended Improvements: a secret manager in production; key rotation procedures (Level 18)
```

## Level 3 - FastAPI foundation

**Goal.** An HTTP layer that is safe before any business logic exists.

**Built.** `src/aegis/main.py` (app factory, middleware order), `src/aegis/middleware/`
(request context and trusted-proxy client IP, security headers, error boundary, body-size and
content-type limits, RFC 9457 problems), `src/aegis/api/errors.py`, `src/aegis/api/health.py`,
versioned router `src/aegis/api/router.py`.

**Concepts.** Middleware ordering; problem details; request correlation; streaming body limits;
trusted proxies and the right-most `X-Forwarded-For` rule.

**Common mistakes avoided.** Stack traces or exception text in responses; trusting the left-most
forwarded address; reading unbounded bodies; echoing invalid input in 422 responses.

**Verify.** `uv run pytest tests/security/test_api_security.py tests/unit/test_request_context.py`.

```text
Security Review
Threats:              information leakage, header injection, host-header attacks, oversized bodies, CSRF-style form posts
Attack Surface:       every HTTP request
Current Protections:  security headers, TrustedHost, content-type enforcement, body limits,
                      generic errors, sanitised request ids, docs off in production
Remaining Risks:      no authentication yet; no rate limiting yet
Recommended Improvements: authentication and rate limits (Level 5), TLS proxy (Level 18)
```

## Level 4 - Database and models

**Goal.** A schema that protects itself: constraints, encryption, migrations, least-privilege roles.

**Built.** `src/aegis/db/` (naming conventions, `UTCDateTime`, `EncryptedText`, `JSONType`,
engine with statement timeouts and SQLite pragmas), `src/aegis/models/` (20 tables),
`src/aegis/repositories/` (ownership-scoped queries, row locks, atomic transitions),
`migrations/` (0001 schema, 0002 PostgreSQL hardening), `docker/postgres/init/01-roles.sh`,
`src/aegis/seed.py` (fictional business).

**Concepts.** CHECK constraints for closed sets and money consistency; partial unique indexes;
application-level column encryption with key rotation; append-only audit trail; owner vs runtime
roles; `alembic check` for drift.

**Common mistakes avoided.** String-built SQL; storing card numbers; enums that make migrations
painful; the application connecting as the schema owner or a superuser.

**Verify.** `uv run aegis migrate`; on PostgreSQL:
`AEGIS_TEST_DATABASE_URL=... uv run pytest tests/integration/test_migrations_postgres.py`.

```text
Security Review
Threats:              SQL injection, data exposure from dumps, audit tampering, privilege escalation via the DB role
Attack Surface:       queries, backups, database credentials
Current Protections:  parameter binding only, encrypted sensitive columns, no card data, token digests,
                      runtime role without DDL or audit write access, append-only trigger
Remaining Risks:      the owner role can drop the trigger (visible, auditable DDL)
Recommended Improvements: ship audit events to write-once storage (security audit R-6)
```

## Level 5 - Authentication and authorisation

**Goal.** Know exactly who is calling and what they may do - on every request.

**Built.** `src/aegis/security/passwords.py` (Argon2id, policy, dummy verification, concurrency
cap), `src/aegis/security/tokens.py` (JWT + opaque tokens), `src/aegis/services/auth.py` (login,
lockout, rotation with reuse detection, logout, password change and reset),
`src/aegis/security/totp.py` and `src/aegis/services/mfa.py` (TOTP two-factor authentication with
recovery codes, replay protection and a staff policy),
`src/aegis/security/rbac.py` (4 roles, 33 permissions), `src/aegis/services/authz.py`,
`src/aegis/api/deps.py` (principal from the database, permission dependencies, rate limits),
`src/aegis/api/v1/auth.py`, `src/aegis/services/users.py`.

**Concepts.** Server-side sessions behind short JWTs; refresh-token rotation and theft
detection; enumeration-safe errors and timing; capability plus ownership; `404` for foreign
records; NIST SP 800-63B password rules.

**Common mistakes avoided.** Long-lived JWTs without revocation; refresh tokens stored in plain
text; different errors for unknown accounts; authorisation only in the UI; `403` that confirms a
record exists.

**Verify.** `uv run pytest tests/integration/test_auth_api.py tests/unit/test_passwords_tokens.py`.

```text
Security Review
Threats:              credential stuffing, token forgery/theft, enumeration, IDOR, privilege escalation
Attack Surface:       /auth endpoints, Authorization header, every resource route
Current Protections:  Argon2id, lockout, per-IP/per-account limits, pinned JWT validation,
                      DB-backed sessions, rotation + reuse detection, RBAC + SQL ownership
Remaining Risks:      session theft after a successful sign-in (bearer tokens)
Recommended Improvements: WebAuthn/passkeys and SSO for staff (security audit R-11)
```

## Level 6 - Basic LLM integration

**Goal.** Call Claude safely, cheaply and replaceably.

**Built.** `src/aegis/llm/types.py`, `base.py` (provider interface), `anthropic_provider.py`
(official SDK: adaptive thinking with effort, strict tools, refusal handling, server-side
fallback, prompt caching, opaque user metadata), `pricing.py`, `gateway.py` (model routing,
budgets, timeouts, circuit breaker, offline fallback, usage accounting),
`src/aegis/agents/offline.py` (deterministic provider).

**Concepts.** A single gateway for every model call; degraded mode instead of outages; cost
accounting per call; never sending personal data or identities to the provider.

**Common mistakes avoided.** SDK calls scattered through the code; no timeouts; retrying
non-idempotent work blindly; forced tool choice; ignoring `stop_reason`.

**Verify.** `uv run pytest tests/unit/test_llm_layer.py tests/llm`.

```text
Security Review
Threats:              data leakage to the provider, cost exhaustion, provider outage, unsafe output
Attack Surface:       prompts, responses, API keys
Current Protections:  redacted input (Level 8), opaque metadata, budgets, circuit breaker, offline fallback
Remaining Risks:      model output is still untrusted text
Recommended Improvements: validate every output (Levels 7 and 12)
```

## Level 7 - Structured LLM outputs

**Goal.** Machine-readable model output that is validated, not trusted.

**Built.** `src/aegis/llm/schema.py` (strict JSON schema from Pydantic models: no extra
properties, all fields required, constraints moved to validation), structured output for
classification and summaries, Pydantic validation of every result, strict tool input models in
`src/aegis/tools/catalog.py`.

**Concepts.** Constrained decoding is a convenience; server-side validation is the guarantee;
schema design for LLMs (closed enums, bounded strings).

**Common mistakes avoided.** `json.loads` on model text without validation; trusting that a
"strict" schema was honoured; letting unknown fields through.

**Verify.** `uv run pytest tests/unit/test_llm_layer.py tests/unit/test_domain_intents.py -k schema`.

```text
Security Review
Threats:              malformed or malicious structured output, schema confusion
Attack Surface:       classifier and summary responses, tool arguments
Current Protections:  strict schemas, Pydantic re-validation, fallbacks on failure
Remaining Risks:      a valid-looking but wrong value (e.g. an order number from another customer)
Recommended Improvements: cross-check values against deterministic facts (Level 8)
```

## Level 8 - Intent classification

**Goal.** Understand each message - intent, priority, sentiment - in a way an attacker cannot
steer into unsafe decisions.

**Built.** `src/aegis/agents/intents.toml` (11 intents, tools and knowledge per intent),
`intents.py` (validated registry), `signals.py` (deterministic signals), `rules.py`
(keyword classifier), `classifier.py` (structured output + validation + cross-checks + fallback),
`src/aegis/security/redaction.py` and `text.py` (model view of the message).

**Concepts.** Deterministic signals that the model cannot override; priority can only go up;
order numbers must appear in the text; confidence capping on disagreement.

**Common mistakes avoided.** Letting the classifier's output switch off escalation; sending raw
PII to the model; trusting model-extracted identifiers.

**Verify.** `uv run pytest tests/unit/test_domain_intents.py tests/llm -k classification`.

```text
Security Review
Threats:              classifier manipulation, misrouting to privileged flows, PII exposure
Attack Surface:       customer text
Current Protections:  signals OR-ed into escalation, validation, rule fallback, redaction
Remaining Risks:      misclassification of benign but unusual requests
Recommended Improvements: clarify-then-handoff policy (Level 12) and quality metrics (Level 17)
```

## Level 9 - RAG pipeline

**Goal.** Answer policy questions from company documents - including hostile ones - with
citations.

**Built.** `src/aegis/security/uploads.py`, `src/aegis/services/knowledge.py` (quarantine,
approval, versioning, indexing), `src/aegis/rag/chunking.py`, `embeddings.py` (hashing and
Voyage AI), `retriever.py` (validation, authority ordering, budgets), prompt fencing in
`src/aegis/agents/prompts.py`, `data/knowledge_base/`.

**Concepts.** Indirect prompt injection; documents as data; latest-version resolution; context
budgets; citations and honest "I don't know".

**Common mistakes avoided.** Indexing uploads without review; parsing rich formats; letting
document text into the instruction channel; unbounded context.

**Verify.** `uv run pytest tests/unit/test_rag.py tests/integration/test_desk_admin_api.py -k knowledge`.

```text
Security Review
Threats:              poisoned documents, internal-document disclosure, conflicting policies, parser exploits
Attack Surface:       uploads, retrieval results
Current Protections:  text-only uploads, quarantine, chunk screening (indexing and retrieval),
                      fencing, visibility filtering (Level 10), authority ordering
Remaining Risks:      subtle misinformation in an approved document
Recommended Improvements: second approver for quarantined documents (security audit R-5)
```

## Level 10 - Vector database

**Goal.** Semantic search that enforces who may see what.

**Built.** `src/aegis/rag/vector_store.py` (Qdrant server or embedded; payload indexes;
deterministic point ids; visibility and category filters inside the query; dimension checks),
Compose service with API key, `aegis index-kb` and `--rebuild`.

**Concepts.** Authorisation inside the vector query plus a post-check; rebuildable indexes;
refusing incompatible vector sizes.

**Common mistakes avoided.** Filtering by visibility only after retrieval; mixing embedding
models in one collection; exposing the vector database publicly.

**Verify.** `uv run pytest tests/integration/test_conversations_api.py -k internal_documents`.

```text
Security Review
Threats:              cross-audience retrieval, unauthenticated vector-store access, index corruption
Attack Surface:       Qdrant API, search filters
Current Protections:  filter in the query, post-check with a security event, API key, private network
Remaining Risks:      plain HTTP to Qdrant inside the Docker network
Recommended Improvements: TLS to Qdrant across hosts (security audit R-7)
```

## Level 11 - Tool calling

**Goal.** Let the model use business functions without handing it the business.

**Built.** `src/aegis/tools/base.py`, `catalog.py` (13 tools, minimal outputs), `registry.py`,
`executor.py` (allow-list, budgets, cache, schema validation, RBAC, timeout, safe errors,
evidence, audit), `src/aegis/services/actions.py` (propose-then-confirm).

**Concepts.** Tools as a security boundary; least privilege per turn; data minimisation in tool
output; TOCTOU-safe confirmation; atomic state transitions.

**Common mistakes avoided.** Tools that take a customer id from the model; tools that execute
refunds; trusting provider-side schema validation; returning whole database rows.

**Verify.** `uv run pytest tests/security/test_agent_security.py -k tool`.

```text
Security Review
Threats:              malicious tool requests, parameter manipulation, excessive agency, runaway loops
Attack Surface:       tool calls produced by the model
Current Protections:  per-intent allow-lists, strict schemas, RBAC, ownership in services,
                      budgets, timeouts, confirmation for state changes, audit
Remaining Risks:      read tools can still expose the signed-in customer's own data to a manipulated reply
Recommended Improvements: output guard (Level 12)
```

## Level 12 - Agent orchestration

**Goal.** One reliable, bounded, validated turn from message to reply.

**Built.** `src/aegis/agents/orchestrator.py` (locking, screening, persistence, policy,
retrieval, tool loop, one corrective retry, persistence, escalation, audit), `policy.py`
(decision table, write-tool removal), `guard.py` (leaks, secrets, grounding, links, PII,
citations, length), `responses.py`, `prompts.py` (system prompt with canary).

**Concepts.** Deterministic policy around a probabilistic model; evidence-based output
validation; per-conversation locks; turn deadlines; safe fallbacks.

**Common mistakes avoided.** Showing raw model output; unlimited retries; letting a failed turn
surface as a 500; concurrent turns in one conversation.

**Verify.** `uv run pytest tests/security/test_agent_security.py tests/llm`.

```text
Security Review
Threats:              prompt leaks, exfiltration via links/images, hallucinated facts, loops, concurrency bugs
Attack Surface:       model replies, concurrent requests
Current Protections:  guard (block/retry/sanitise), iteration and time bounds, locks, fallbacks
Remaining Risks:      free-text policy claims are not machine-verified
Recommended Improvements: red-team evaluation with the real model (security audit R-4)
```

## Level 13 - Conversation memory

**Goal.** Context across turns without unbounded cost or a growing injection surface.

**Built.** `src/aegis/agents/memory.py` (bounded history window of redacted text, rolling summary
without personal data, short-term state as validated JSON with TTL).

**Concepts.** Memory as untrusted data; summaries as data minimisation; plain-text history replay.

**Common mistakes avoided.** Replaying whole transcripts; pickling state; persisting reasoning
blocks; storing summaries in clear text.

**Verify.** `uv run pytest tests/llm -k "history or summar"`.

```text
Security Review
Threats:              injection persistence across turns, PII accumulation, cost growth
Attack Surface:       history and summaries sent to the model
Current Protections:  redacted and truncated history, character budgets, encrypted summaries, JSON state with TTL
Remaining Risks:      an injected instruction may be summarised into later turns (still fenced as data)
Recommended Improvements: keep monitoring guard metrics per conversation
```

## Level 14 - Human handoff

**Goal.** Hand the conversation to people whenever the machine should not decide.

**Built.** `src/aegis/services/handoff.py` (idempotent escalation with tickets, queue, claim,
assign, reply, resolve), `src/aegis/api/v1/desk.py`, `src/aegis/services/tickets.py`,
escalation triggers in the policy and the orchestrator.

**Concepts.** Deterministic escalation for security, legal, explicit requests, repeated failures
and suspicious activity; the assistant stops answering while a human handles the case.

**Common mistakes avoided.** Letting the model decide whether "my account was hacked" needs a
human; duplicate tickets for repeated triggers; staff acting as customers.

**Verify.** `uv run pytest tests/integration/test_desk_admin_api.py -k handoff`.

```text
Security Review
Threats:              escalation suppression by injection, staff overreach, queue flooding
Attack Surface:       escalation triggers, agent-desk endpoints
Current Protections:  signal-based escalation, per-permission desk actions, audit, ticket limits per day
Remaining Risks:      staff can read any conversation (by role)
Recommended Improvements: MFA and access reviews for staff (security audit R-1)
```

## Level 15 - Security hardening

**Goal.** Close the gaps between components.

**Built.** Egress policy (`src/aegis/core/egress.py`), idempotency keys
(`src/aegis/services/idempotency.py`), sliding-window rate limits that never fail open
(`src/aegis/kv/rate_limit.py`), distributed locks, log redaction
(`src/aegis/observability/logging.py`), injection detector hardening (normalisation forms,
bounded regexes), per-IP limit on the whole API, empty-means-unset secrets, data-subject rights
(`src/aegis/services/privacy.py`: export, erasure, retention), the Stripe refund adapter with
signed webhooks (`src/aegis/services/payments.py`, `src/aegis/security/webhooks.py`).

**Concepts.** SSRF prevention; fail-closed vs fail-open; idempotency semantics; ReDoS.

**Common mistakes avoided.** Following redirects to internal hosts; rate limiters that disappear
when Redis does; retries that duplicate payments; logging request bodies.

**Verify.** `uv run pytest tests/unit/test_egress_resilience.py tests/unit/test_kv_rate_limit.py tests/security/test_redos.py tests/unit/test_logging.py`.

```text
Security Review
Threats:              SSRF, DoS, replay, log leakage, ReDoS, forged payment events, over-retention
Attack Surface:       outbound HTTP, all endpoints, logs, regex-based detectors, webhooks, stored personal data
Current Protections:  allow-listed HTTPS egress without redirects, layered rate limits,
                      idempotency, redaction filter, linear-time patterns, HMAC-verified
                      webhooks with a replay window, export/erasure/retention
Remaining Risks:      distributed attacks from many IPs and accounts
Recommended Improvements: edge protection (WAF/bot management), global budget alerts
```

## Level 16 - Testing and security testing

**Goal.** Prove every claim.

**Built.** About 470 tests: unit, integration, security (IDOR matrix, privilege escalation,
token forgery, injection, tool abuse, guard bypass, exfiltration, ReDoS, second-factor abuse,
forged webhooks), LLM behaviour with a scripted model and the real SDK over a mocked transport,
PostgreSQL hardening, deployment configuration and documentation truthfulness
([testing.md](testing.md)); `scripts/check.py` runs every gate.

**Concepts.** Attack scenarios as regression tests; testing the system around the model rather
than the model; running the same suite on SQLite and PostgreSQL.

**Common mistakes avoided.** Only happy-path tests; mocking the thing under test; tests that
depend on a live model.

**Verify.** `uv run pytest --cov` and the quality gates in [testing.md](testing.md#quality-gates).

```text
Security Review
Threats:              regressions, untested controls, documentation drift
Attack Surface:       every change
Current Protections:  security test suite, coverage gate, strict typing, lint security rules,
                      bandit, pip-audit, import contracts, generated docs checks
Remaining Risks:      none open: CI runs every gate, the image scan and the dynamic API tests on
                      every change (security audit R-3)
Recommended Improvements: mutation testing of the security suite
```

## Level 17 - Observability and monitoring

**Goal.** See what the system does - especially what attackers try - without logging secrets.

**Built.** JSON logs with request correlation and redaction, Prometheus metrics with bounded
labels (`src/aegis/observability/metrics.py`), security-event counters, the audit trail and its
API, model-usage accounting, readiness without details, heartbeat health for the worker
([operations.md](operations.md)).

**Concepts.** Events and identifiers instead of content; cardinality control; audit vs logs.

**Common mistakes avoided.** Logging prompts and replies; user input as metric labels; health
endpoints that reveal hostnames.

**Verify.** `uv run pytest tests/unit/test_logging.py` and
`uv run pytest tests/integration/test_desk_admin_api.py -k "health or audit"`.

```text
Security Review
Threats:              blind spots during attacks, secrets in logs, metrics as a data leak
Attack Surface:       logs, /metrics, /health/ready, audit API
Current Protections:  redaction filter, bearer-protected metrics, bounded labels, audit permissions
Remaining Risks:      logs and audit rows live on infrastructure an attacker might reach
Recommended Improvements: ship them to a SIEM / write-once storage with alerts (security audit R-6)
```

## Level 18 - Docker and deployment

**Goal.** A production-like deployment that keeps the least-privilege design.

**Built.** `Dockerfile` (multi-stage, locked dependencies, non-root, health check),
`docker-compose.yml` (internal network, loopback-only API, per-container variables, hardened
containers, Redis ACL, Qdrant API key, unprivileged images), `docker/postgres/init/01-roles.sh`,
`aegis init-env --docker`, `aegis healthcheck`, [deployment.md](deployment.md) with the
production checklist and rotation procedures.

**Concepts.** Immutable images; secrets injected at runtime; defence in depth at the container
level; separating migration credentials from runtime credentials.

**Common mistakes avoided.** Running as root; `env_file` handing every secret to every
container; publishing databases; superuser migrations; `latest` tags.

**Verify.** `uv run pytest tests/integration/test_deployment.py` (configuration). The image and
the stack were not built on the development machine; the CI workflow builds and smoke-tests them.
The production packaging was verified locally: `uv sync --frozen --no-dev --no-editable` into a
clean environment and the whole lifecycle run from a folder holding only what the Dockerfile
copies.

```text
Security Review
Threats:              container breakout, lateral movement, secret sprawl, misconfiguration
Attack Surface:       images, Compose configuration, networks, database init
Current Protections:  non-root read-only containers without capabilities, internal network,
                      least-privilege roles and variables, pinned images, tested configuration
Remaining Risks:      unbuilt, unscanned images; plain HTTP between containers
Recommended Improvements: CI build, image scanning and signing; TLS across hosts (R-3, R-7)
```

## Level 19 - Performance and cost optimisation

**Goal.** Fast enough and cheap enough, predictably.

**Built.** Model routing (capable model only for replies and tools; small model for
classification and summaries), prompt caching of the static prefix, per-turn tool-result cache,
query-embedding cache, bounded history and context, output caps, budgets per user and per day,
async I/O throughout with CPU-heavy hashing in threads, database indexes for the hot queries,
keyset-batched maintenance jobs, the worker for indexing.

**Concepts.** Cost as a security property (denial of wallet); caching without leaking between
users (keys scoped by embedder and query fingerprint; per-turn tool cache); latency budgets.

**Common mistakes avoided.** One large model for everything; unbounded context growth; hashing
passwords on the event loop; cross-user caches.

**Verify.** `uv run pytest tests/llm -k "budgets or fenced"`; `GET /api/v1/admin/llm-usage`.

```text
Security Review
Threats:              denial of wallet, resource exhaustion, cache poisoning
Attack Surface:       message endpoint, caches, worker
Current Protections:  rate limits, budgets (fail closed), caps, scoped caches, offline fallback
Remaining Risks:      many accounts can still consume up to the global budget
Recommended Improvements: spend alerts and per-tenant budgets if the platform becomes multi-tenant
```

## Level 20 - Final production-like review

**Goal.** Review everything as an attacker and as an operator would, fix what is found, and
state honestly what remains.

**Done.** A full code and configuration review, the final threat model, the OWASP LLM Top 10
mapping and the final audit with 21 findings fixed (two high: an empty metrics token accepted,
superuser migrations in Compose), the recommendations implemented in the audit (staff two-factor
authentication, data-subject rights, a real payment provider, CI), the complete documentation, the
end-to-end demo against a live server, the production-packaging check, and all quality gates on
SQLite and PostgreSQL. See [security-audit.md](security-audit.md).

```text
Security Review
Threats:              all of the above, end to end
Attack Surface:       the whole system
Current Protections:  the controls in security-architecture.md, each verified by a test
Remaining Risks:      unbuilt images, provider integrations not exercised live, live-model red-teaming
Recommended Improvements: security audit R-3 to R-11
```
