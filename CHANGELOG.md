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

Defects found before the release by testing the running system (each has a regression test;
details in docs/security-audit.md, F-22 to F-26):

- **Docker Compose:** the Redis ACL is passed as an exec-form list. As a command string, Compose
  read the `>` of the password rule as a shell redirection and dropped the rest of the line
  (password, key pattern, command restrictions, memory cap), so Redis refused every client.
  Found when CI first started the stack.
- **API input validation:** boolean fields in request bodies (`approve` on a refund decision,
  `is_active` on an account, `return_to_ai` on a handoff) accept only JSON booleans. Lax
  coercion turned `0`, `"no"` or `"false"` into `false` and `1` or `"yes"` into `true`. Found by
  Schemathesis.
- **API input validation:** an out-of-range `before` cursor on the message history caused a
  database error and a `500`; it is now a `422`. Found by Schemathesis.
- **API input validation:** undeclared query parameters are rejected with a `422`, as unknown
  body fields already were; a misspelt filter no longer returns unfiltered results. Found by
  Schemathesis.
- **HTTP semantics:** a `405 Method Not Allowed` response lists every method the resource
  supports in `Allow` (RFC 9110); a path served by two routes advertised only one of them.
  Found by Schemathesis.

[1.0.0]: https://github.com/mojtaba-py-code/secure-ai-customer-support-platform/releases/tag/v1.0.0
