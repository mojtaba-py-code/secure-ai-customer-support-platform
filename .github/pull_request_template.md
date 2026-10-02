## What and why

<!-- What this change does and the problem it solves. -->

## Checklist

- [ ] `uv run python scripts/check.py` passes (lint, format, types, architecture, bandit, audit, docs, tests)
- [ ] New behaviour is covered by tests; security-relevant behaviour by a `@pytest.mark.security` test
- [ ] Docs updated (`scripts/generate_docs.py` for settings, tools and endpoints)
- [ ] No secrets, real personal data or host-specific paths in the diff

## Security impact

<!-- Authentication, authorisation, data reaching the model, tools, stored data, dependencies -
     or "none". See docs/threat-model.md. -->
