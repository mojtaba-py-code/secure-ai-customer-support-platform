# Contributing

Thank you for helping. Security problems are **not** reported through issues or pull requests -
see [SECURITY.md](SECURITY.md).

## Development setup

Requirements: Python 3.12 or newer and [uv](https://docs.astral.sh/uv/).

```bash
uv sync                      # the locked environment, with the development tools
uv run aegis init-env        # .env with fresh development secrets (never commit it)
uv run aegis migrate && uv run aegis seed
uv run aegis serve           # http://127.0.0.1:8000/docs
```

## Before opening a pull request

```bash
uv run python scripts/check.py     # every quality gate CI runs, on SQLite
```

To run the suite on PostgreSQL as well, point `--postgres` at a disposable database:
`uv run python scripts/check.py --postgres postgresql+asyncpg://...`.

- Keep the layering: `uv run lint-imports` enforces which package may import which.
- Add tests with the change; mark security regressions with `@pytest.mark.security`.
- Regenerate the generated documentation with `uv run python scripts/generate_docs.py`.
- Never commit secrets, real personal data, `.env` files or anything under `var/`.
- Commits to `main` are signed; please sign yours (`git commit -S`).

## Pull request flow

`main` is protected: changes arrive through pull requests whose CI checks pass (static analysis,
tests on SQLite and PostgreSQL, dependency audit, secret scan, workflow audit, container and
end-to-end checks, dynamic security tests). The pull-request template lists what reviewers look
for, including the security impact of the change.
