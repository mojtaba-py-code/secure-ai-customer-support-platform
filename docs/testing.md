# Testing

The suite is designed so that every security property the documentation claims is demonstrated
by a test, and so that it runs anywhere: by default it needs no network, no Docker and no API
key (SQLite in memory, embedded Qdrant, the in-process key-value store and a scripted or offline
model). The same suite also runs on PostgreSQL.

## Running the tests

```bash
uv run python scripts/check.py                 # every quality gate below, as CI runs them
uv run pytest                                  # everything (about 470 tests)
uv run pytest tests/unit                       # fast, no database
uv run pytest -m security                      # attack scenarios only
uv run pytest -m llm                           # model-behaviour tests
uv run pytest --cov                            # with coverage (fails under 85 %)
uv run pytest -k refund                        # by name
```

On PostgreSQL (a disposable database; the suite drops and recreates the `public` schema):

```bash
AEGIS_TEST_DATABASE_URL=postgresql+asyncpg://user:password@127.0.0.1:5432/aegis_test uv run pytest
```

With a role that may create roles, this also runs `tests/integration/test_migrations_postgres.py`,
which rebuilds the production role layout and proves the database hardening (see below).

## Layout

| Directory | Tests | What they cover |
|---|---|---|
| `tests/unit` | ~312 | Settings and production rules, text normalisation and redaction, injection detection, passwords and tokens, TOTP (RFC 6238 test vectors) and recovery codes, RBAC, encryption, uploads, egress and resilience, rate limiting, RAG components, domain rules and intents, the output guard, the LLM layer (Claude adapter against a mocked transport, gateway, schemas), the Stripe adapter and webhook signatures, logging redaction, client-IP resolution |
| `tests/integration` | ~97 | The HTTP API end to end: authentication and two-factor flows, commerce, conversations and pending actions, the agent desk and administration, privacy requests, payment webhooks, CLI commands and the worker, deployment files, documentation consistency, and the PostgreSQL migration test |
| `tests/security` | ~54 | Attack scenarios against the API and the agent: IDOR matrix, privilege escalation, forged tokens, headers, body limits, content types, error leakage, prompt injection, tool abuse, output-guard bypasses, data exfiltration, ReDoS |
| `tests/llm` | ~10 | Behaviour with realistic model output: malformed classification, low confidence, least-privilege tool exposure, history replay, provider outage, conflicting policy versions, summaries, fenced context |

Shared fixtures (`tests/conftest.py`): `make_settings()` (test settings, fast Argon2 parameters),
`build_container()` (a fresh database schema and in-memory stores per test), `seeded` /
`seeded_kb` (the demo business, optionally with the indexed knowledge base), `client` (an HTTP
client against the ASGI app with a fixed client address) and `login`. Test doubles
(`tests/fakes.py`): `ScriptedLLM`, which plays back a script of classifications, tool calls,
replies or exceptions and records every request it receives, and `CapturingEmailSender`.

## How the model is tested

Three complementary techniques:

1. **Scripted model** - `ScriptedLLM` replaces the provider. A test scripts exactly what "the
   model" does (for example: call `request_refund` for another customer's order, then claim the
   refund is done) and asserts what the *system* does about it. The recorded requests prove what
   the model was shown (no raw PII, fenced context, only the allowed tools).
2. **Official SDK with a mocked transport** - the Claude adapter is exercised through the real
   `anthropic` SDK with an `httpx2.MockTransport`, checking the request shape (strict tools,
   effort, structured output, caching, metadata) and the handling of refusals, `max_tokens`,
   malformed JSON and transport errors.
3. **Offline model** - the deterministic stand-in runs the whole pipeline in the integration
   tests and the demo, so every flow is exercised end to end without an API key.

## Security test catalogue

| Attack | Tests |
|---|---|
| Reading other customers' data via the API | `test_idor_matrix_between_customers`, `test_customers_see_only_their_orders`, `test_ticket_access_control_and_staff_updates` |
| Reading other customers' data via the assistant | `test_another_customers_order_cannot_be_read_through_tools`, `test_other_customers_orders_are_not_disclosed` |
| Privilege escalation | `test_privilege_escalation_is_blocked`, `test_staff_cannot_confirm_customer_actions`, `test_refund_review_is_restricted_to_managers` |
| Token forgery and stale privileges | `test_forged_and_malformed_tokens_are_rejected`, `test_role_changes_apply_to_existing_tokens`, `test_deactivated_user_loses_access_immediately` |
| Session attacks | `test_refresh_rotation_and_reuse_detection`, `test_logout_revokes_immediately`, `test_password_change_revokes_other_sessions` |
| Second-factor abuse | `test_sign_in_needs_the_second_factor` (replay), `test_wrong_codes_lock_the_account`, `test_a_challenge_dies_after_five_wrong_codes`, `test_a_totp_step_can_be_claimed_only_once`, `test_recovery_codes_work_once`, `test_enrolment_requires_password_and_a_valid_code`, `test_staff_without_mfa_have_no_permissions_when_it_is_required` |
| Payment abuse | `test_forged_and_irrelevant_events_change_nothing`, `test_invalid_signatures_are_rejected`, `test_approved_refund_completes_through_the_signed_webhook` (duplicate and late events), `test_only_the_configured_host_is_reachable` |
| Privacy | `test_customers_export_everything_about_themselves`, `test_staff_cannot_export_and_exports_are_rate_limited`, `test_erasure_is_admin_only_confirmed_and_waits_for_open_work`, `test_erasure_anonymises_the_customer_irreversibly`, `test_retention_period_erases_old_finished_conversations` |
| Brute force and enumeration | `test_login_rate_limit_per_ip`, `test_account_lockout_after_repeated_failures`, `test_login_me_and_generic_failures`, `test_reset_requests_are_capped_per_account` |
| Floods and resource abuse | `test_api_is_rate_limited_per_client_ip_even_without_a_valid_token`, `test_rate_limits_follow_the_real_client_behind_a_trusted_proxy`, `test_llm_endpoint_rate_limit`, `test_oversized_bodies_are_rejected_before_processing`, `test_detectors_stay_linear_on_hostile_input` |
| Direct prompt injection | `test_injection_in_the_message_is_fenced_as_data`, `test_flagged_messages_lose_write_tools`, `test_repeated_attacks_escalate_the_conversation`, `test_invisible_character_attacks_are_normalised_and_refused` |
| Indirect prompt injection (documents) | `test_malicious_document_is_quarantined_until_approved`, `test_internal_documents_never_reach_customers` |
| Excessive agency | `test_tools_outside_the_turn_allow_list_are_refused`, `test_unknown_tools_are_refused`, `test_malicious_tool_arguments_are_rejected`, `test_tool_call_budget_and_loop_limits`, `test_the_model_cannot_execute_a_refund_by_itself` |
| Output attacks | `test_system_prompt_leak_is_blocked`, `test_exfiltration_links_and_foreign_pii_are_stripped`, `test_hallucinated_facts_trigger_one_correction_then_a_safe_fallback` |
| Sensitive data handling | `test_llm_never_receives_raw_pii_or_card_numbers`, `test_ticket_description_never_stores_card_numbers`, `test_conversation_subjects_never_store_card_numbers`, `test_message_content_is_encrypted_at_rest`, `test_secrets_and_recovery_codes_are_not_stored_in_clear`, `tests/unit/test_logging.py` |
| Information leakage | `test_internal_errors_do_not_leak_details`, `test_validation_errors_never_echo_input`, `test_readiness_reports_failures_without_details`, `test_security_headers_on_success_and_error_responses` |
| Business-logic abuse | `test_refund_proposal_confirmation_and_idempotency`, `test_declined_and_expired_actions`, `test_shipped_orders_cannot_be_cancelled`, `test_expired_refund_window_is_explained`, `test_message_idempotency` |
| Upload abuse | `test_upload_validation_and_permissions` (permissions, path traversal, executables, invalid metadata) and the upload unit tests in `tests/unit/test_rbac_crypto_uploads.py` (sizes, encodings, magic numbers, control characters) |
| Database hardening (PostgreSQL) | `test_migrations_build_a_hardened_schema` |
| Deployment misconfiguration | `tests/integration/test_deployment.py` (no `env_file`, no owner secrets in runtime containers, hardening flags, loopback-only publishing, pinned images, least-privilege roles, compose/CLI secret consistency) |

## The PostgreSQL hardening test

`test_migrations_build_a_hardened_schema` creates a throw-away schema owner (no superuser) and a
runtime role, then:

1. runs `alembic upgrade head` as the owner and `alembic check` (no drift between the models and
   the migrations);
2. proves the runtime role can read and write application data but gets *permission denied* for
   `UPDATE`/`DELETE`/`TRUNCATE` on `audit_events`, writing `alembic_version`, `CREATE TABLE`,
   and *must be owner* for `DROP TABLE` and `ALTER TABLE`;
3. proves that even the owner is stopped by the append-only trigger;
4. runs `downgrade base` and `upgrade head` again.

## Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request, without secrets:

| Job | What it runs |
|---|---|
| Static analysis | ruff, ruff format, mypy, import-linter, bandit, `uv lock --check`, `generate_docs.py --check` |
| Tests (Python 3.12, 3.13, 3.14, SQLite) | the full suite with branch coverage (coverage and JUnit reports kept as artifacts) |
| Tests (PostgreSQL 16) | the full suite on PostgreSQL, including the migration and database-hardening test |
| Dependency audit | `pip-audit` over the hash-pinned export of `uv.lock` |
| Secret scan | gitleaks over the whole history (`.github/gitleaks.toml` allows the synthetic secrets under `tests/`) |
| Workflow security | zizmor over `.github/` |
| Container | image build, image policy, Trivy (image and Dockerfile), CycloneDX SBOM, then the Compose stack: readiness, migration exit code, no data-service port on the host, seed, and `scripts/demo.py` against the stack |
| DAST | the API started with demo data (`scripts/dast_token.py` signs in), Schemathesis as an administrator and as a customer (every check except `positive_data_acceptance`, whose false positives are invalid tokens and empty uploads, and `use_after_free`, since `DELETE` archives a knowledge-base document on purpose), and an OWASP ZAP API scan (`.github/zap/rules.tsv`) |

`codeql.yml` (Python and Actions, `security-extended`) and `supply-chain.yml` (dependency review,
OpenSSF Scorecard, weekly Trivy scans of the third-party images) run beside it.

### Dynamic testing locally

```bash
uv run aegis serve &                                     # after init-env, migrate and seed
TOKEN=$(uv run python scripts/dast_token.py --role admin)
uvx --from schemathesis st run http://127.0.0.1:8000/openapi.json   -H "Authorization: Bearer $TOKEN" --checks all --exclude-checks positive_data_acceptance   --exclude-path-regex '(logout|revoke-sessions)'
```

Raise the `AEGIS_RL_*` limits for such a run (as CI does), or the limiter answers `429` before the
handlers are reached.

## Quality gates

| Gate | Command | Purpose |
|---|---|---|
| Tests with coverage | `uv run pytest --cov` | Behaviour; line and branch coverage must stay at or above 85 % |
| Lint | `uv run ruff check .` | Style, bugs, security rules (flake8-bandit), banned APIs (`pickle`, `marshal`, `shelve`, `os.system`, HTTP clients outside the egress module, YAML) |
| Format | `uv run ruff format --check .` | One formatting style |
| Types | `uv run mypy` | `strict` mode with the Pydantic plugin over the source and the tests |
| Architecture | `uv run lint-imports` | Layer contracts and forbidden imports (see [architecture.md](architecture.md#layers)) |
| Static security analysis | `uv run bandit -c pyproject.toml -r src` | Insecure patterns |
| Dependencies | `uv run pip-audit` | Known vulnerabilities in the locked dependency tree |
| Generated docs | `uv run python scripts/generate_docs.py --check` | The configuration, API and tools references match the code |

Warnings are errors in the test run (`filterwarnings = error`), so deprecations and unawaited
coroutines fail the build instead of piling up.

## Latest results

On the development machine (Windows 10, Python 3.12, 2026-09-30):

- SQLite: all tests pass, coverage above the 85 % gate;
- PostgreSQL 16: all tests pass, including the hardening test;
- ruff, ruff format, mypy (strict), import-linter, bandit, pip-audit: no findings;
- the generated documentation is in sync;
- the production packaging (the container's `uv sync --no-dev --no-editable` install) runs the
  whole lifecycle, the demo and a live two-factor and privacy session.

The exact numbers of the final run are recorded in [security-audit.md](security-audit.md#evidence).
