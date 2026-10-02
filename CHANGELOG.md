# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-10-03

First public release.

### Added

- **AI assistant**: intent, priority and sentiment classification with schema-validated
  structured output and a rule-based fallback; a deterministic turn policy (answer, clarify,
  refuse, escalate); a bounded tool loop; grounded replies with citations; conversation memory
  with rolling summaries; Claude through an LLM gateway with token and cost budgets, a circuit
  breaker and an offline fallback model.
- **Knowledge base (RAG)**: Markdown-aware chunking, local or Voyage AI embeddings, Qdrant with
  visibility filtering inside the vector search, authority ordering, prompt-injection screening
  at upload and at retrieval, quarantine and approval, versioning.
- **13 tools** (orders, payments, refunds, cancellations, tickets, products, profile, human
  handoff) with strict schemas, per-intent allow-lists, per-turn budgets, RBAC and ownership
  checks; state-changing actions are only proposed and need the customer's confirmation.
- **Support operations**: human-handoff queue, tickets, manager refund review with Stripe
  refunds (idempotent requests, signed webhooks), knowledge-base administration, audit trail,
  model usage and cost reports.
- **Privacy**: data export, erasure requests, irreversible anonymisation, retention periods.
- **Security**: Argon2id, TOTP two-factor authentication with recovery codes (required for staff
  in production), rotating refresh tokens with reuse detection, lockout, RBAC (33 permissions,
  4 roles), field-level encryption, PII redaction before the model, output guard, SSRF-safe
  egress, rate limits, idempotency keys, security headers, append-only audit trail,
  least-privilege PostgreSQL roles and Redis ACL.
- **Operations**: JSON logs with redaction, Prometheus metrics, health probes, background worker,
  a CLI for every operational task, a hardened Docker image and Compose stack.
- **CI/CD**: static analysis, tests on Python 3.12-3.14 and PostgreSQL 16, dependency audit,
  secret scanning, CodeQL, container scanning and SBOM, the Compose stack driven end to end,
  Schemathesis and OWASP ZAP against the running API, workflow audit, OpenSSF Scorecard, and
  signed releases with build provenance.

### Fixed

Found by fuzzing the running API with Schemathesis before the first release:

- Boolean fields in request bodies (`approve` on a refund decision, `is_active` on an account,
  `return_to_ai` on a handoff) accept only JSON booleans. Lax coercion used to turn `0`, `"no"`
  or `"false"` into `false` and `1` or `"yes"` into `true`, so a malformed client could reject
  or approve a refund, or deactivate an account, without sending a boolean.
- A `405 Method Not Allowed` response lists every method the resource supports in `Allow`
  (RFC 9110); a path served by two routes used to advertise only one of them.

[1.0.0]: https://github.com/mojtaba-py-code/secure-ai-customer-support-platform/releases/tag/v1.0.0
