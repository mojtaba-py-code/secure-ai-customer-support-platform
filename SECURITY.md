# Security policy

## Reporting a vulnerability

**Please do not report security problems in a public issue, discussion or pull request.**
Report them privately, by either of these channels:

- **GitHub private vulnerability reporting** (preferred): the
  [*Report a vulnerability*](https://github.com/mojtaba-py-code/secure-ai-customer-support-platform/security/advisories/new)
  button on the repository's **Security** tab. The report, the discussion and the fix stay
  private until a security advisory is published.
- **E-mail**: [mojtaba.python@gmail.com](mailto:mojtaba.python@gmail.com) with the subject line
  `[SECURITY] AegisSupport AI`.

Please include what you found, the affected version or commit, the steps to reproduce it (a
request sequence, a payload or a failing test is ideal) and the impact you expect.

| Step | Target |
|---|---|
| Acknowledgement of the report | within 3 business days |
| First assessment (confirmed or not, severity) | within 7 days |
| Fix or mitigation for a critical or high-severity issue | within 14 days of confirmation |
| Fix for a medium or low-severity issue | in the next release |
| Public advisory (CVE requested where applicable), crediting the reporter if they wish | after the fix is released |

### Safe harbour

Good-faith research that follows this policy is welcome and will not be pursued. Test only
against your own deployment (the project runs fully offline with fictional demo data - see the
[quick start](README.md#quick-start-no-docker-no-api-key)); never against anyone else's data or
systems. Do not run denial-of-service tests against shared infrastructure, do not use social
engineering, and stop and report as soon as you reach a vulnerability.

### Scope

In scope: the application code in `src/`, the database migrations, the container image and the
Compose stack, the default configuration, and the CI/CD workflows in `.github/`. This includes
the LLM-specific attack surface: prompt injection (direct, and indirect through knowledge-base
documents), tool misuse, cross-customer data access through the assistant, system-prompt or
secret leakage, and unsafe output.

Out of scope: vulnerabilities in third-party services (Claude API, Voyage AI, Stripe) and in
dependencies that are already publicly known - but please do tell us if the project ships an
affected version, since the dependency audit should have caught it.

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | yes |
| < 1.0 | no |

Security fixes are released as patch versions and announced in a GitHub security advisory.

## How the project is kept secure

The security design, its threat model and the final audit are documented in:

- [docs/security-architecture.md](docs/security-architecture.md) - controls by layer
- [docs/threat-model.md](docs/threat-model.md) - assets, trust boundaries, threats, mitigations,
  and the OWASP Top 10 for LLM Applications mapping
- [docs/security-audit.md](docs/security-audit.md) - findings, fixes, evidence and residual risks

The properties that matter most are enforced by automated tests (`pytest -m security`, the
two-factor, privacy and payment-webhook suites, and the PostgreSQL hardening test): no
cross-customer data access through the API or the assistant, no state change without the
customer's confirmation, no refund marked paid unless the payment provider confirmed it (its
authenticated API answer or a signed webhook), no secrets or unredacted personal data sent to the
model or written to logs, and an append-only audit trail.

Every change to `main` is also checked by CI ([`.github/workflows`](.github/workflows)):

| Layer | Tooling |
|---|---|
| Code | ruff (including the `S` security rules), mypy (strict), import-linter architecture contracts, Bandit, CodeQL (`security-extended`, Python and GitHub Actions) |
| Dependencies | pip-audit over the hash-pinned lock file, Dependabot (security and version updates), dependency review on pull requests |
| Secrets | gitleaks over the full history; GitHub secret scanning with push protection |
| Container | digest-pinned base images, Trivy (image vulnerabilities and Dockerfile misconfiguration), a CycloneDX SBOM, an image policy check (unprivileged user, read-only root filesystem, no pip) |
| Running system | the Compose stack driven end to end; Schemathesis property-based fuzzing of every API operation as a customer and as an administrator; an OWASP ZAP API scan |
| CI/CD itself | zizmor workflow audit, actions pinned to commit SHAs, read-only default tokens, no secrets in CI, OpenSSF Scorecard |
| Releases | images signed keyless with Sigstore cosign, with SLSA build provenance and SBOM attestations |

## Operating it securely

Before exposing a deployment, work through the production checklist in
[docs/deployment.md](docs/deployment.md#production-checklist). In short: run with
`AEGIS_ENV=production` (the process refuses unsafe settings, including staff accounts without
two-factor authentication and the simulated payment provider), keep secrets in a secret manager,
terminate TLS in front of the API, use the least-privilege database and Redis accounts, keep the
data services on a private network, rotate keys on a schedule, and watch the security metrics
and audit events described in [docs/operations.md](docs/operations.md).

To verify a released container image before deploying it:

```bash
cosign verify ghcr.io/mojtaba-py-code/secure-ai-customer-support-platform:1.0.0 \
  --certificate-identity-regexp '^https://github.com/mojtaba-py-code/secure-ai-customer-support-platform/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/mojtaba-py-code/secure-ai-customer-support-platform:1.0.0 \
  --repo mojtaba-py-code/secure-ai-customer-support-platform
```

The wheel and the source distribution on the GitHub release carry a cosign bundle each
(`*.sigstore.json`) and the SLSA provenance (`aegis_support.intoto.jsonl`):

```bash
cosign verify-blob aegis_support-1.0.0-py3-none-any.whl \
  --bundle aegis_support-1.0.0-py3-none-any.whl.sigstore.json \
  --certificate-identity-regexp '^https://github.com/mojtaba-py-code/secure-ai-customer-support-platform/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify aegis_support-1.0.0-py3-none-any.whl \
  --repo mojtaba-py-code/secure-ai-customer-support-platform
```

## Third-party images

The Compose stack runs PostgreSQL, Redis and Qdrant from their official images, pinned by
digest. A weekly job (`supply-chain.yml`) scans them as pinned and lists their fixable HIGH and
CRITICAL findings in its summary. Those are packages inside the upstream images (for example the
`gosu` helper, OpenSSL in the Alpine base, or Node.js modules bundled with Qdrant) that this
repository cannot patch; the remedy is a newer pin once upstream publishes a rebuilt image, which
Dependabot proposes. They are kept out of code scanning, which tracks this project's own code and
container image. In production, keep the data services on a private network, as the Compose file
does, and follow the upstream projects' security advisories.

## Code-scanning triage

Alerts that were reviewed and dismissed, with the reason:

| Rule | Location | Reason |
|---|---|---|
| `py/weak-sensitive-data-hashing` | `src/aegis/security/tokens.py` (`hash_opaque_token`) | Hashes only 256-bit random opaque tokens (sessions, refresh, password-reset and MFA-challenge tokens from `secrets.token_urlsafe(32)`), never passwords - those use Argon2id. A fast hash is the standard construction for high-entropy tokens. |
| `py/clear-text-logging-sensitive-data` | `src/aegis/cli.py` (`generate-secrets`) | The command's purpose is to print freshly generated secrets for the operator to store in a secret manager; nothing is logged. `init-env` writes them to an owner-only file instead. |
| `py/clear-text-logging-sensitive-data` | `src/aegis/cli.py` (`create-admin`) | Prints only the fixed password-policy messages (for example "is too common"), never the password. |
