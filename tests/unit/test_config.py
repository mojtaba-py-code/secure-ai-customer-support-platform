from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from pydantic import ValidationError

from aegis.core.config import Settings, load_settings
from tests.conftest import make_settings

GOOD_SECRET = "prod-grade-secret-7f3b2c9d1e0a4b5c6d7e8f9a0b1c2d3e"


def production(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "env": "production",
        "database_url": "postgresql+asyncpg://aegis_app:pw@db:5432/aegis",
        "redis_url": "redis://aegis:pw@redis:6379/0",
        "qdrant_url": "http://qdrant:6333",
        "jwt_secret": GOOD_SECRET,
        "field_encryption_keys": Fernet.generate_key().decode(),
        "allowed_hosts": "support.acme.example",
        "cors_origins": "https://support.acme.example",
        "email_backend": "smtp",
        "smtp_host": "smtp.acme.example",
        "metrics_token": "metrics-token-value-1234567890",
        "hsts_enabled": True,
        "mfa_required_for_staff": True,
        "payment_provider": "stripe",
        "stripe_api_key": "rk_live_restricted_0123456789",
        "stripe_webhook_secret": "whsec_0123456789abcdef",
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)  # type: ignore[arg-type]


def test_defaults_and_comma_separated_lists() -> None:
    settings = make_settings(
        cors_origins="https://a.example, https://b.example", allowed_hosts="a,b"
    )
    assert settings.cors_origins == ["https://a.example", "https://b.example"]
    assert settings.allowed_hosts == ["a", "b"]
    assert settings.docs_enabled is True
    assert make_settings(database_url="sqlite+aiosqlite:///:memory:").is_sqlite
    assert not make_settings(database_url="postgresql+asyncpg://u:p@db/aegis").is_sqlite


def test_secrets_never_appear_in_repr() -> None:
    settings = make_settings()
    text = repr(settings)
    assert "test-jwt-secret" not in text
    assert settings.field_encryption_keys.get_secret_value() not in text


def test_short_jwt_secret_rejected_without_echoing_it() -> None:
    with pytest.raises(ValidationError) as info:
        make_settings(jwt_secret="short-secret")
    assert "short-secret" not in str(info.value)


def test_low_variety_jwt_secret_rejected() -> None:
    with pytest.raises(ValidationError):
        make_settings(jwt_secret="a" * 40)


def test_invalid_fernet_key_rejected() -> None:
    with pytest.raises(ValidationError):
        make_settings(field_encryption_keys="not-a-fernet-key")


def test_multiple_fernet_keys_supported() -> None:
    keys = f"{Fernet.generate_key().decode()},{Fernet.generate_key().decode()}"
    assert len(make_settings(field_encryption_keys=keys).encryption_keys) == 2


def test_anthropic_provider_requires_key() -> None:
    with pytest.raises(ValidationError):
        make_settings(llm_provider="anthropic")


def test_provider_base_urls_must_be_https() -> None:
    with pytest.raises(ValidationError):
        make_settings(anthropic_base_url="http://proxy.local")


def test_valid_production_configuration_is_accepted() -> None:
    settings = production()
    assert settings.is_production
    assert settings.docs_enabled is False


@pytest.mark.parametrize(
    ("override", "fragment"),
    [
        ({"database_url": "sqlite+aiosqlite:///x.db"}, "SQLite"),
        ({"redis_url": None}, "AEGIS_REDIS_URL"),
        ({"qdrant_url": None}, "AEGIS_QDRANT_URL"),
        ({"cors_origins": "*"}, "AEGIS_CORS_ORIGINS"),
        ({"cors_origins": "http://support.acme.example"}, "https://"),
        ({"allowed_hosts": "*"}, "AEGIS_ALLOWED_HOSTS"),
        ({"email_backend": "dev_mailbox"}, "mailbox"),
        ({"metrics_token": None}, "AEGIS_METRICS_TOKEN"),
        ({"hsts_enabled": False}, "HSTS"),
        ({"database_echo": True}, "ECHO"),
        ({"log_level": "DEBUG"}, "DEBUG"),
        ({"log_json": False}, "AEGIS_LOG_JSON"),
        ({"mfa_required_for_staff": False}, "AEGIS_MFA_REQUIRED_FOR_STAFF"),
        (
            {
                "payment_provider": "simulated",
                "stripe_api_key": None,
                "stripe_webhook_secret": None,
            },
            "simulated payment provider",
        ),
        ({"jwt_secret": "change-me-please-this-is-a-placeholder-secret"}, "placeholder"),
    ],
)
def test_unsafe_production_configuration_is_refused(
    override: dict[str, object], fragment: str
) -> None:
    with pytest.raises(ValidationError) as info:
        production(**override)
    assert fragment.lower() in str(info.value).lower()


def test_rag_settings_cross_validation() -> None:
    with pytest.raises(ValidationError):
        make_settings(rag_chunk_chars=300, rag_chunk_overlap_chars=300)
    with pytest.raises(ValidationError):
        make_settings(rag_top_k=10, rag_candidate_k=5)


def test_metrics_token_must_be_strong() -> None:
    with pytest.raises(ValidationError, match="AEGIS_METRICS_TOKEN"):
        make_settings(metrics_token="short")
    assert make_settings(metrics_token="x" * 16).metrics_token is not None


@pytest.fixture
def clean_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """No developer .env and no inherited AEGIS_* variables."""
    import os

    monkeypatch.chdir(tmp_path)
    for name in list(os.environ):
        if name.startswith("AEGIS_"):
            monkeypatch.delenv(name)
    return tmp_path


def test_empty_variables_mean_unset(clean_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``AEGIS_METRICS_TOKEN=`` must not become an empty (always matching) credential."""
    monkeypatch.setenv("AEGIS_JWT_SECRET", GOOD_SECRET)
    monkeypatch.setenv("AEGIS_FIELD_ENCRYPTION_KEYS", Fernet.generate_key().decode())
    monkeypatch.setenv("AEGIS_METRICS_TOKEN", "")
    monkeypatch.setenv("AEGIS_REDIS_URL", "")
    monkeypatch.setenv("AEGIS_ANTHROPIC_API_KEY", "")
    settings = load_settings()
    assert settings.metrics_token is None
    assert settings.redis_url is None
    assert settings.anthropic_api_key is None
    monkeypatch.setenv("AEGIS_LLM_PROVIDER", "anthropic")
    with pytest.raises(ValidationError, match="AEGIS_ANTHROPIC_API_KEY"):
        load_settings()


def test_secrets_can_be_mounted_as_files(clean_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secrets_dir = clean_env / "secrets"
    secrets_dir.mkdir()
    key = Fernet.generate_key().decode()
    (secrets_dir / "AEGIS_JWT_SECRET").write_text(GOOD_SECRET + "\n", encoding="utf-8")
    (secrets_dir / "AEGIS_FIELD_ENCRYPTION_KEYS").write_text(key, encoding="utf-8")
    (secrets_dir / "AEGIS_METRICS_TOKEN").write_text(
        "file-metrics-token-0123456789", encoding="utf-8"
    )
    monkeypatch.setenv("AEGIS_SECRETS_DIR", str(secrets_dir))
    monkeypatch.setenv("AEGIS_METRICS_TOKEN", "env-metrics-token-0123456789")  # env wins
    settings = load_settings()
    assert settings.jwt_secret.get_secret_value() == GOOD_SECRET
    assert settings.encryption_keys == [key]
    assert settings.metrics_token is not None
    assert settings.metrics_token.get_secret_value() == "env-metrics-token-0123456789"


def test_missing_secrets_dir_is_an_error(clean_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_SECRETS_DIR", str(clean_env / "does-not-exist"))
    with pytest.raises(ValueError, match="AEGIS_SECRETS_DIR"):
        load_settings()


def test_stripe_needs_both_secrets_and_https() -> None:
    with pytest.raises(ValidationError, match="AEGIS_STRIPE_API_KEY"):
        make_settings(payment_provider="stripe", stripe_api_key="rk_test_0123456789")
    with pytest.raises(ValidationError, match="https"):
        make_settings(
            payment_provider="stripe",
            stripe_api_key="rk_test_0123456789",
            stripe_webhook_secret="whsec_0123456789",
            stripe_base_url="http://api.stripe.com",
        )
    settings = make_settings(
        payment_provider="stripe",
        stripe_api_key="rk_test_0123456789",
        stripe_webhook_secret="whsec_0123456789",
    )
    assert settings.stripe_api_key is not None
    assert "rk_test" not in repr(settings)
