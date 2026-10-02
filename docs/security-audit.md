# Final security audit

| | |
|---|---|
| System | AegisSupport AI 1.0.0 |
| Date | 2026-09-30; updated 2026-10-03 for the publication (dynamic testing, container and CI verification) |
| Scope | All application code (`src/aegis`), migrations, configuration, CLI, worker, container and Compose files, database init script, CI configuration, documentation claims |
| Method | Full code review against the threat model; OWASP Top 10 for LLM Applications (2025) mapping; automated attack tests; static analysis (ruff security rules, bandit); strict typing (mypy); architecture contracts (import-linter); dependency audit (pip-audit); database hardening verified on a real PostgreSQL 16 server; production packaging verified the way the container uses it; end-to-end demo and a live two-factor/privacy session against a running server. For the publication: property-based fuzzing with Schemathesis of 56 of the 58 API operations (the two sign-out endpoints are excluded so that the session survives), as an administrator and as a customer, locally and in CI - about 100,000 generated requests; an OWASP ZAP API scan; container scanning (Trivy) and the Compose stack driven end to end in CI; a workflow security audit (zizmor); and secret scanning of the full history (gitleaks) |
| Not in scope / not possible here | Live calls to the Claude, Voyage AI and Stripe APIs (adapters tested against simulated transports using the providers' formats); an external penetration test; load testing |

## Summary

The platform treats the language model as an untrusted component and enforces every
security-relevant decision in deterministic code: authorisation and ownership in the services and
SQL, tool access in the policy and executor, state changes only after an out-of-band customer
confirmation, and output validation before anything reaches a customer. Staff sign in with a
second factor, customers can export and erase their data, and refunds move money only through an
idempotent, webhook-confirmed provider flow. The audit found and fixed the issues listed below;
**no known high or critical issue remains open**. The remaining risks are operational (building
and scanning the images, exercising the provider integrations against their test environments,
live red-teaming against the real model) and are listed with recommendations.

## Findings

Severity follows impact x likelihood for this system. All findings are fixed and covered by a
regression test unless stated otherwise.

| ID | Severity | Finding | Fix | Regression test |
|---|---|---|---|---|
| F-01 | High | An empty `AEGIS_METRICS_TOKEN=` (as in an example file) became an empty secret, so `/metrics` accepted `Authorization: Bearer ` with no token. | Empty variables now mean "unset" (`env_ignore_empty`); the token must have 16+ characters; production requires it. | `test_empty_variables_mean_unset`, `test_metrics_token_must_be_strong` |
| F-02 | High | In the Compose stack the schema-owner role used by migrations was the PostgreSQL bootstrap **superuser**, so a compromised migration job (or leaked owner password) had full cluster control. | A dedicated bootstrap superuser used only by the init script; `aegis_owner` is `NOSUPERUSER NOCREATEDB NOCREATEROLE` and owns only the application database. Verified on PostgreSQL 16. | `test_database_roles_are_least_privilege`, `test_migrations_build_a_hardened_schema` |
| F-03 | Medium | Application containers loaded the whole `.env` (`env_file`), so the API and worker received the superuser and owner database passwords they never need. | No `env_file`; each container receives an explicit variable list; the migration job gets only the owner URL. | `test_no_service_loads_a_whole_env_file`, `test_runtime_containers_never_receive_owner_or_superuser_secrets`, `test_migration_job_receives_only_what_it_needs` |
| F-04 | Medium | The per-IP API limit (`AEGIS_RL_API_PER_IP_PER_MINUTE`) was defined but never applied, so floods of requests with invalid tokens were not throttled at all. | Applied to every `/api/v1` route before authentication; behind a proxy it follows the real client address. | `test_api_is_rate_limited_per_client_ip_even_without_a_valid_token`, `test_rate_limits_follow_the_real_client_behind_a_trusted_proxy` |
| F-05 | Medium | Conflicting knowledge-base documents (a newer refund policy of 45 days and an older FAQ saying 30) could produce a wrong policy answer. | Authority ordering by the intent's primary category, an explicit prompt rule, latest version per slug, offline-model support. | `test_conflicting_policy_versions_resolve_to_the_newest` |
| F-06 | Medium | The Redis container dropped all capabilities while its entrypoint starts as root and switches user with `su-exec` (needs `SETUID`/`SETGID`): the service would not start. | Run the container directly as the image's `redis` user. | `test_containers_are_hardened` |
| F-07 | Medium | The container health check called the API with `Host: 127.0.0.1`, which the host filter rejects in production (the container would be restarted as unhealthy); the worker inherited an HTTP health check it could never pass. | `aegis healthcheck` sends an allowed `Host`; the worker writes a heartbeat file checked by `aegis healthcheck --worker`. | `test_api_healthcheck_uses_an_allowed_host`, `test_worker_healthcheck_reads_the_heartbeat`, `test_worker_loop_writes_its_heartbeat` |
| F-08 | Medium | Conversation subjects were stored in a plain column without the storage redaction every other free-text field gets: a card number typed into a subject would have been persisted in clear. | Subjects pass `redact_for_storage` like messages and tickets. | `test_conversation_subjects_never_store_card_numbers` |
| F-09 | Low | Text logging (allowed in production) prints tracebacks, which can contain parameters and personal data; readable logs omitted audit context. | Production requires JSON logs (no tracebacks); the development format prints the scrubbed extra fields. | `test_unsafe_production_configuration_is_refused`, `test_text_format_shows_scrubbed_extra_fields_and_request_id` |
| F-10 | Low | `aegis rotate-encryption` loaded whole tables into memory, could overwrite rows changed concurrently, and relied on a hand-maintained column list. | Keyset batches with `SELECT ... FOR UPDATE`; encrypted columns discovered from the models (now including the TOTP secrets). | `test_full_cli_lifecycle`, `test_rotation_covers_every_encrypted_column` |
| F-11 | Low | `aegis create-admin` accepted malformed e-mail addresses, crashed with a traceback on duplicates and was not audited. | Validated with the API's schema, friendly duplicate error, `admin.user_create` audit event. | `test_full_cli_lifecycle` |
| F-12 | Low | Changing the embedding dimensions had no safe rebuild path for a Qdrant server (the process correctly refuses mismatched collections). | `aegis index-kb --rebuild` fills a new, empty collection; documented procedure. | `test_full_cli_lifecycle` |
| F-13 | Low | Injection-only messages received a clarifying question (engaging the attacker); a security report sent while a human handled the conversation did not raise its priority; repeated failures escalated one turn late. | New `refuse` decision without a model call; priority bump for security/legal messages in human-handled conversations; escalation in the failing turn. | `test_repeated_attacks_escalate_the_conversation`, `test_repeated_failures_escalate_to_a_human`, `test_escalation_hands_the_conversation_to_humans` |
| F-14 | Low | The database init script started with `set -eu`; the official PostgreSQL entrypoint *sources* non-executable init scripts, so `-u` could leak into the entrypoint's shell and break the first start. | `set -e` only (the `:?` checks still fail fast); verified by running the script both executed and sourced against PostgreSQL 16. | `test_database_roles_are_least_privilege` |
| F-15 | Low | Public error `details` (the reasons an order cannot be cancelled, failed password rules, why an erasure must wait, the payment provider's refusal code) were dropped from responses, so clients could not explain a refusal. | `details` are part of the problem document; the contract that they must be public data is documented on `AegisError`. | `test_erasure_is_admin_only_confirmed_and_waits_for_open_work` |
| F-16 | Low | The new TOTP verifier would have failed with an internal error on codes written in non-ASCII digits (e.g. full-width or Persian digits: `isdigit()` accepts them, `compare_digest` does not). Found by a test before release. | Codes must be ASCII digits. | `test_malformed_codes_are_rejected` |
| F-17 | Low | Alembic's logging configuration disabled the application's loggers inside the same process. | `disable_existing_loggers=False`. | - |
| F-18 | Info | With FastAPI's lazily included routers the metrics and access-log `route` label lost the `/api/v1` prefix. | Every v1 router carries the full prefix. | `test_metrics_label_requests_with_the_full_route_template` |
| F-19 | Info | `python -m importlinter.cli` exits 0 without checking anything, so a CI gate written that way would always pass. | `scripts/check.py` calls the real command; verified that it reports the contracts. | - |
| F-20 | Info | Dead code (an unused repository, helpers and constants) and three `assert`s used for type narrowing (removed under `python -O`). | Removed; explicit type checks instead of `assert`. | bandit: no findings |
| F-22 | Low | Boolean fields in request bodies were validated in lax mode: `{"approve": 0}` rejected a refund and `{"is_active": "no"}` deactivated an account, although the schema says boolean. A buggy or confused privileged client could change money or access state without sending a boolean. Found by Schemathesis (negative-data checks). | `StrictBool` on every boolean request field (`approve`, `is_active`, `return_to_ai`). | `test_refund_decision_requires_a_json_boolean`, `test_staff_user_management` |
| F-23 | Info | A `405 Method Not Allowed` for a path served by two routes (`GET` and `POST /api/v1/conversations`) listed only one method in `Allow` (RFC 9110, section 15.5.6). Found by Schemathesis. | The error handler lists every method any route serves for the path. | `test_method_not_allowed_lists_every_supported_method` |
| F-24 | Medium | The Redis `command` was a single string. Compose splits it shell-style and read the unquoted `>` of the ACL password rule as a redirection, silently dropping the password, the `aegis:*` key pattern, the command restrictions, the memory cap and the no-persistence settings. The service failed closed (no client could authenticate), but the stack could not start. Found when CI first ran the stack (health check: `WRONGPASS`). | Exec-form command list; every Compose `command` must be a list. | `test_commands_are_exec_form_lists` |
| F-25 | Low | `GET /conversations/{id}/messages?before=<n>` had no upper bound: a value beyond the 32-bit column range raised a database error and a 500 (no data was exposed - the handler returns only the request id). Found by Schemathesis as a customer. | `before` is bounded to the column range; out-of-range values are a 422. | `test_conversation_lifecycle_and_history` |
| F-26 | Low | Undeclared query parameters were silently ignored, while request bodies already reject unknown fields. A misspelt filter (`?stauts=open`) returned unfiltered results instead of an error. Found by Schemathesis (negative-data checks). | Every `/api/v1` route rejects query parameters it does not declare with a 422 that does not echo the name; a test keeps the accepted set equal to the OpenAPI document. | `test_unknown_query_parameters_are_rejected`, `test_every_documented_query_parameter_is_accepted` |
| F-21 | Info | Missing tests for security controls that existed: log redaction, client-IP resolution behind proxies, the password-hashing concurrency cap, regular-expression DoS resistance, and the truthfulness of the documentation. | Tests added. | `tests/unit/test_logging.py`, `tests/unit/test_request_context.py`, `test_concurrent_hashing_is_capped`, `tests/security/test_redos.py`, `tests/integration/test_documentation.py` |

## Recommendations implemented in this audit

| ID | Recommendation | Implementation | Evidence |
|---|---|---|---|
| R-1 | Multi-factor authentication for staff | TOTP two-factor authentication for every account, with single-use challenges, replay protection, lockout integration, recovery codes and administrator resets; mandatory for staff in production (unenrolled staff hold no permissions) | `tests/unit/test_totp.py` (RFC 6238 vectors), `tests/integration/test_mfa.py`, live session against the production install |
| R-2 | Data-subject requests and retention | Export of all personal data, erasure requests, irreversible administrator erasure with safeguards, conversation retention period | `tests/integration/test_privacy.py` |
| R-9 | A real payment provider | Stripe adapter with idempotency keys, egress policy and error mapping; HMAC-verified webhooks with replay window and idempotent state changes; the simulated gateway refused in production | `tests/unit/test_payments.py`, `tests/integration/test_payment_webhooks.py` |
| R-3 | CI and release verification | `.github/workflows/ci.yml` runs every gate of `scripts/check.py`, the suite on Python 3.12-3.14 and on PostgreSQL 16, pip-audit, gitleaks, zizmor, the container build with an image policy, Trivy and an SBOM, the Compose stack end to end with the demo, and Schemathesis and OWASP ZAP against the running API; CodeQL, Dependabot, dependency review and OpenSSF Scorecard run beside it; releases are signed with cosign and carry SLSA provenance | the CI runs on GitHub (`.github/workflows`) |

## Control verification

Status against the security requirements of the project brief.

| Area | Status | Evidence |
|---|---|---|
| LLM treated as untrusted; prompt and indirect injection; jailbreaks; system-prompt extraction; data exfiltration | Implemented in depth (fencing, detector, risk-adaptive tools, refusal, escalation, guard) | `tests/security/test_agent_security.py`, `tests/llm/test_llm_behaviour.py` |
| Malicious tool requests, parameter manipulation, excessive calls, infinite loops | Implemented (allow-lists, strict schemas, RBAC, budgets, iteration caps, deadline) | `test_tools_outside_the_turn_allow_list_are_refused`, `test_malicious_tool_arguments_are_rejected`, `test_tool_call_budget_and_loop_limits` |
| Hallucinated results and unauthorised actions | Implemented (evidence-grounded guard; propose-then-confirm) | `test_hallucinated_facts_trigger_one_correction_then_a_safe_fallback`, `test_the_model_cannot_execute_a_refund_by_itself` |
| Authentication (hashing, JWT, expiry, refresh security, lockout, reset, session invalidation, auth logging) | Implemented | `tests/integration/test_auth_api.py` |
| Multi-factor authentication | Implemented; mandatory for staff in production | `tests/integration/test_mfa.py`, `tests/unit/test_totp.py` |
| Authorisation (RBAC, ownership, least privilege, staff separation) | Implemented | `test_idor_matrix_between_customers`, `test_privilege_escalation_is_blocked` |
| API security (validation, limits, content types, CORS, headers, errors, versioning, pagination caps) | Implemented | `tests/security/test_api_security.py` |
| Database security (parameterised queries, least-privilege roles, constraints, migrations, transactions, audit immutability) | Implemented; verified on PostgreSQL 16 | `test_migrations_build_a_hardened_schema` |
| Redis security (ACL, key prefix, TTLs, memory cap, safe serialisation, private network) | Implemented in configuration and code; the Redis server itself was not run here | `test_containers_are_hardened`, key-value unit tests |
| Secrets management | Implemented (typed secrets, generation, secret files, no defaults, production checks) | `tests/unit/test_config.py` |
| Customer data protection (minimisation, redaction, encryption, no card storage) | Implemented | `test_llm_never_receives_raw_pii_or_card_numbers`, `test_message_content_is_encrypted_at_rest`, `test_ticket_description_never_stores_card_numbers`, `test_conversation_subjects_never_store_card_numbers` |
| Data-subject rights (access, erasure, retention) | Implemented | `tests/integration/test_privacy.py` |
| Logging and audit | Implemented | `tests/unit/test_logging.py`, `test_audit_trail_and_usage_endpoints` |
| Error handling and resilience (timeouts, retries, circuit breaker, degradation) | Implemented | `test_provider_outage_degrades_to_the_offline_model`, `tests/unit/test_egress_resilience.py` |
| Idempotency | Implemented (API, pending actions, payment provider) | `test_message_idempotency`, `test_refund_proposal_confirmation_and_idempotency`, `test_approved_refund_completes_through_the_signed_webhook` |
| Payment integration (idempotent refunds, signed webhooks) | Implemented; not exercised against the live Stripe API | `tests/unit/test_payments.py`, `tests/integration/test_payment_webhooks.py` |
| Rate limiting and abuse prevention | Implemented | see D1-D5 in the [threat model](threat-model.md#stride) |
| LLM cost control | Implemented | `test_llm_endpoint_rate_limit`, gateway unit tests |
| Human handoff | Implemented | `test_human_handoff_workflow` |
| Secure external requests (SSRF) | Implemented | `tests/unit/test_egress_resilience.py`, `test_only_the_configured_host_is_reachable` |
| Secure file handling | Implemented (text formats only; malware scanning not applicable, see [rag.md](rag.md#upload-validation)) | `test_upload_validation_and_permissions` |
| Container hardening | Implemented in configuration; **images not built or scanned here** (the CI workflow does it) | `tests/integration/test_deployment.py` |

## Evidence

Final verification run on 2026-09-30 (Windows 10, Python 3.12) on the final code:

| Check | Result |
|---|---|
| Test suite on SQLite with coverage (`pytest --cov`) | **472 passed**, 1 skipped (the PostgreSQL-only test); line + branch coverage **90.54 %** (gate: 85 %) |
| Test suite on PostgreSQL 16 (`AEGIS_TEST_DATABASE_URL=...`) | **473 passed** - every test, including the migration and hardening test (revisions 0001-0003) |
| `python scripts/check.py` (all gates) | all 10 gates passed (lint, format, types, architecture, static security, dependency audit, lock file, generated docs, both test suites) |
| `ruff check .` / `ruff format --check .` | no findings |
| `mypy` (strict, 168 files) | no issues |
| `lint-imports` | 5 contracts kept, 0 broken |
| `bandit -c pyproject.toml -r src` | no issues |
| `pip-audit` | no known vulnerabilities |
| `uv lock --check` | lock file consistent with `pyproject.toml` |
| `python scripts/generate_docs.py --check` | in sync |
| Migrations | upgrade, `alembic check` (no drift), downgrade and re-upgrade on SQLite and PostgreSQL 16 |
| Database init script on PostgreSQL 16 | creates non-superuser `aegis_owner` and `aegis_app`, correct ownership and default privileges; works executed and sourced |
| Production packaging (the container's install) | `uv sync --frozen --no-dev --no-editable` into a clean environment (no development tools installed); from a folder holding only `alembic.ini`, `migrations/` and `data/`: `migrate`, `seed`, `index-kb`, `worker`, `serve`, `healthcheck` (API and worker heartbeat), the demo, and a live session: TOTP enrolment, old sessions revoked, password-only login refused, replayed code refused, recovery-code sign-in, data export, erasure request |
| Quick start + `scripts/demo.py` against a live server (fresh folder) | all flows as documented: order status from tool data; refund prepared, then confirmed through the API (`pending_review`); injection refused; another customer's order "not found"; escalation with a ticket; agent claim and reply |

## Residual risks

| Risk | Rating | Notes |
|---|---|---|
| Novel prompt injections bypass the heuristic detector | Medium likelihood, low impact | By design the impact is bounded (own data only, validated output, no unconfirmed state changes). |
| Wrong policy statements that the guard cannot detect | Low-medium | The guard checks references and amounts, not free-text claims; citations and authority ordering reduce the risk. |
| Staff session theft (phished password and code, stolen device) | Low-medium | MFA, 15-minute access tokens, refresh-token theft detection and immediate revocation limit it; staff can still read any conversation by role. |
| Provider integrations not exercised live (Claude, Voyage AI, Stripe) | Medium (operational) | Request and response formats are tested with simulated transports; run each against the provider's test environment before production (R-10). |
| Unverified container build | Medium (operational) | Configuration and packaging are tested, the image build is not; the CI workflow covers it once it runs (R-3). |
| Insider actions by administrators | Low | Approvals, resets and erasures are audited but not dual-controlled (R-5). |
| Degraded (offline) answers are less helpful and English-only | Low | Availability over fluency; flagged `degraded`. |

## Recommendations

| ID | Priority | Recommendation |
|---|---|---|
| R-3 | High | Run the CI workflow on every change; add image scanning (e.g. Trivy/Grype) and signing to the `container` job. |
| R-10 | High | Before production, run the Claude, Voyage AI and Stripe integrations against their test environments (Stripe test mode with its CLI webhook forwarding) and keep those runs as a release check. |
| R-4 | Medium | Run a red-team evaluation against the real Claude models with a corpus of injection and exfiltration prompts, and keep it as a regression suite; monitor the guard metrics in production. |
| R-5 | Medium | Require a second administrator for quarantined-document approval, second-factor resets and customer erasure (separation of duties). |
| R-6 | Medium | Ship audit events to write-once storage or a SIEM; alert on the security events listed in [operations.md](operations.md#alerts). |
| R-7 | Medium | Enable TLS between the application and PostgreSQL, Redis and Qdrant whenever they run on separate hosts; put a WAF or bot protection at the edge. |
| R-8 | Low | Automate key rotation (JWT secret, Fernet keys, database, Redis and provider keys) on a schedule. |
| R-11 | Low | Offer WebAuthn/passkeys and single sign-on for staff in addition to TOTP. |
