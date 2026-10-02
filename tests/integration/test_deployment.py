"""Deployment artefacts: the security properties of docker-compose.yml, the Dockerfile and the
database init script are tested like code, because a regression there is a security regression.

These tests read the files; they do not need Docker.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml  # noqa: TID251 - reads docker-compose.yml in a test (safe_load only)

from aegis import cli
from tests.conftest import ROOT

COMPOSE = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
SERVICES: dict[str, dict[str, Any]] = COMPOSE["services"]
APP_SERVICES = ("migrate", "api", "worker", "seed")
PRIVILEGED_SECRETS = ("POSTGRES_PASSWORD", "AEGIS_DB_OWNER_PASSWORD")


def environment(service: str) -> dict[str, str]:
    return {k: str(v) for k, v in (SERVICES[service].get("environment") or {}).items()}


def test_no_service_loads_a_whole_env_file() -> None:
    for name, service in SERVICES.items():
        assert "env_file" not in service, name


@pytest.mark.parametrize("service", ["api", "worker", "seed"])
def test_runtime_containers_never_receive_owner_or_superuser_secrets(service: str) -> None:
    env = environment(service)
    for secret in PRIVILEGED_SECRETS:
        assert secret not in env
        assert all(secret not in value for value in env.values()), secret
    assert env["AEGIS_DATABASE_URL"].startswith("postgresql+asyncpg://aegis_app:")
    assert "AEGIS_MIGRATION_DATABASE_URL" not in env


def test_migration_job_receives_only_what_it_needs() -> None:
    env = environment("migrate")
    assert set(env) == {"AEGIS_MIGRATION_DATABASE_URL", "AEGIS_DB_APP_ROLE"}
    assert env["AEGIS_MIGRATION_DATABASE_URL"].startswith("postgresql+asyncpg://aegis_owner:")
    assert env["AEGIS_DB_APP_ROLE"] == "aegis_app"


def test_containers_are_hardened() -> None:
    for name, service in SERVICES.items():
        assert "no-new-privileges:true" in service.get("security_opt", []), name
        assert service.get("privileged") is not True, name
        assert service.get("network_mode") != "host", name
    for name in (*APP_SERVICES, "redis"):
        service = SERVICES[name]
        assert service.get("read_only") is True, name
        assert service.get("cap_drop") == ["ALL"], name
    assert SERVICES["redis"].get("user") == "redis"  # cannot switch users without capabilities
    assert SERVICES["qdrant"]["image"].split("@")[0].endswith("-unprivileged")


def test_commands_are_exec_form_lists() -> None:
    # A command string is split shell-style by Compose: an unquoted ">" (Redis' password rule)
    # was read as a redirection and everything after it - the password, the key pattern, the
    # memory cap - was silently dropped, leaving a passwordless ACL user. Found by running the
    # stack in CI (the health check failed with WRONGPASS).
    for name, service in SERVICES.items():
        if "command" in service:
            assert isinstance(service["command"], list), name
            assert all(isinstance(part, str) for part in service["command"]), name
    redis = SERVICES["redis"]["command"]
    rule = redis[redis.index("aegis") :]
    assert rule[:6] == [
        "aegis",
        "on",
        ">${REDIS_PASSWORD:?set REDIS_PASSWORD}",
        "~aegis:*",
        "+@all",
        "-@dangerous",
    ]
    assert redis[redis.index("default") + 1] == "off"
    assert redis[redis.index("--maxmemory") + 1] == "256mb"
    assert redis[redis.index("--save") + 1] == ""
    assert redis[redis.index("--appendonly") + 1] == "no"


def test_only_the_api_is_published_and_only_on_loopback() -> None:
    for name, service in SERVICES.items():
        ports = service.get("ports", [])
        if name == "api":
            assert ports == ["127.0.0.1:8000:8000"]
        else:
            assert not ports, name
    assert COMPOSE["networks"]["backend"]["internal"] is True
    for name in ("postgres", "redis", "qdrant"):
        assert SERVICES[name]["networks"] == ["backend"], name


def test_images_are_pinned() -> None:
    digest = r"@sha256:[0-9a-f]{64}"
    for name, service in SERVICES.items():
        image = service.get("image", "")
        if service.get("build"):  # built from this repository's Dockerfile
            assert re.fullmatch(r"aegis-support:\d+\.\d+\.\d+", image), (name, image)
        else:  # third-party: a version tag for readers, a digest for reproducibility
            assert re.fullmatch(rf"[\w./-]+:v?\d+(\.\d+)+[\w.-]*{digest}", image), (name, image)
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    bases = re.findall(r"^FROM (\S+)", dockerfile, flags=re.MULTILINE)
    assert bases, "no FROM line"
    for base in bases:
        assert re.fullmatch(rf"[\w./-]+:\d+(\.\d+)+[\w.-]*{digest}", base), base
    assert any(base.startswith("python:3.12-slim-") for base in bases)
    assert any(base.startswith("ghcr.io/astral-sh/uv:") for base in bases)
    assert "pip install" not in dockerfile


def test_dockerfile_runs_unprivileged_with_a_working_health_probe() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    users = re.findall(r"^USER (\S+)", dockerfile, flags=re.MULTILINE)
    assert users and users[-1] == "aegis:aegis"
    assert 'CMD ["aegis", "healthcheck"]' in dockerfile
    assert "--no-proxy-headers" in dockerfile and "--no-server-header" in dockerfile
    assert "ADD http" not in dockerfile
    assert SERVICES["worker"]["healthcheck"]["test"] == ["CMD", "aegis", "healthcheck", "--worker"]
    assert environment("worker")["AEGIS_WORKER_HEARTBEAT_FILE"].startswith("/tmp/")


def test_database_roles_are_least_privilege() -> None:
    script = (ROOT / "docker" / "postgres" / "init" / "01-roles.sh").read_text(encoding="utf-8")
    owner = re.search(r"CREATE ROLE aegis_owner[^;]+;", script)
    app = re.search(r"CREATE ROLE aegis_app[^;]+;", script)
    assert owner and app
    for clause in ("NOSUPERUSER", "NOCREATEDB", "NOCREATEROLE"):
        assert clause in owner.group(0) and clause in app.group(0)
    assert "NOINHERIT" in app.group(0)
    assert 'REVOKE ALL ON DATABASE :"db" FROM PUBLIC' in script
    assert re.search(r"^set -e$", script, flags=re.MULTILINE)  # not -u: the script may be sourced
    assert SERVICES["postgres"]["environment"]["POSTGRES_USER"] == "postgres"


def test_docker_env_file_defines_every_variable_compose_requires(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    assert cli.main(["init-env", "--docker"]) == 0
    generated = dict(
        line.split("=", 1)
        for line in (tmp_path / ".env").read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    )
    compose_text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    required = set(re.findall(r"\$\{([A-Z0-9_]+):\?", compose_text))
    assert required, "the compose file should fail fast on missing secrets"
    assert required <= set(generated), required - set(generated)
    assert all(value and re.fullmatch(r"[A-Za-z0-9_=-]+", value) for value in generated.values())
    assert not (tmp_path / "var").exists()  # the Docker variant does not create local folders


def test_env_example_contains_no_secrets() -> None:
    for line in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
        if line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        value = value.split("#", 1)[0].strip()
        if re.search(r"(SECRET|_KEYS?|_TOKEN|PASSWORD)$", name):
            assert value == "", name
