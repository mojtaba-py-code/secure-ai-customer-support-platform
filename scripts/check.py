"""Run every quality gate - the same list locally and in CI.

    python scripts/check.py                    # all gates on SQLite
    python scripts/check.py --postgres URL     # also run the test suite on PostgreSQL
    python scripts/check.py --skip-audit       # offline: skip the dependency vulnerability audit

Exits non-zero when any gate fails and prints a summary table at the end.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable
# uv is the tool that manages the environment, not a package inside it: use the executable on PATH
# (CI installs it with setup-uv) and fall back to `python -m uv` when it was pip-installed instead.
UV = [uv] if (uv := shutil.which("uv")) else [PYTHON, "-m", "uv"]


@dataclass(frozen=True)
class Gate:
    name: str
    command: list[str]
    env: dict[str, str] | None = None


def gates(args: argparse.Namespace) -> list[Gate]:
    selected = [
        Gate("lint", [PYTHON, "-m", "ruff", "check", "."]),
        Gate("format", [PYTHON, "-m", "ruff", "format", "--check", "."]),
        Gate("types", [PYTHON, "-m", "mypy"]),
        Gate(
            "architecture",
            [
                PYTHON,
                "-c",
                "from importlinter.cli import lint_imports_command; lint_imports_command()",
            ],
        ),
        Gate(
            "static security", [PYTHON, "-m", "bandit", "-c", "pyproject.toml", "-r", "src", "-q"]
        ),
        Gate("lock file", [*UV, "lock", "--check"]),
        Gate("generated docs", [PYTHON, "scripts/generate_docs.py", "--check"]),
        Gate("tests (SQLite)", [PYTHON, "-m", "pytest", "-q", "-p", "no:randomly", "--cov"]),
    ]
    if not args.skip_audit:
        selected.insert(5, Gate("dependency audit", [PYTHON, "-m", "pip_audit"]))
    if args.postgres:
        selected.append(
            Gate(
                "tests (PostgreSQL)",
                [PYTHON, "-m", "pytest", "-q", "-p", "no:randomly"],
                env={"AEGIS_TEST_DATABASE_URL": args.postgres},
            )
        )
    return selected


def run(gate: Gate) -> tuple[bool, float]:
    print(
        f"\n=== {gate.name}: {' '.join(Path(part).name if part in {PYTHON, *UV} else part for part in gate.command)}"
    )
    started = time.perf_counter()
    env = {**os.environ, **(gate.env or {})}
    # Arguments are a fixed list (no shell); nothing here comes from user input.
    completed = subprocess.run(gate.command, cwd=ROOT, env=env, check=False)  # noqa: S603
    return completed.returncode == 0, time.perf_counter() - started


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--postgres", metavar="URL", help="postgresql+asyncpg:// URL of a disposable database"
    )
    parser.add_argument("--skip-audit", action="store_true", help="skip pip-audit (needs network)")
    args = parser.parse_args()
    results = [(gate.name, *run(gate)) for gate in gates(args)]
    print("\n" + "-" * 48)
    for name, ok, seconds in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name:<22} {seconds:7.1f} s")
    failed = [name for name, ok, _ in results if not ok]
    print("-" * 48)
    print("all gates passed" if not failed else f"failed: {', '.join(failed)}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
