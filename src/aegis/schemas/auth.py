"""Authentication schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from pydantic import EmailStr, Field, StringConstraints

from aegis.domain.enums import Role
from aegis.schemas.common import RequestModel, ResponseModel

Password = Annotated[str, StringConstraints(min_length=1, max_length=128, strip_whitespace=False)]
OpaqueToken = Annotated[
    str, StringConstraints(min_length=20, max_length=256, pattern=r"^[A-Za-z0-9_-]+$")
]
#: A 6-digit TOTP code or a recovery code such as ``k3vq-8mzt-r2hx-9pwc``.
SecondFactorCode = Annotated[
    str, StringConstraints(min_length=6, max_length=24, pattern=r"^[A-Za-z0-9 -]+$")
]


class LoginRequest(RequestModel):
    email: EmailStr = Field(max_length=254)
    password: Password


class RefreshRequest(RequestModel):
    refresh_token: OpaqueToken


class TokenResponse(ResponseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 - the OAuth token type name, not a secret
    expires_in: int
    access_expires_at: datetime
    refresh_token: str
    refresh_expires_at: datetime


class MfaChallengeResponse(ResponseModel):
    """Returned by ``/auth/login`` instead of tokens when the account uses two-factor auth."""

    mfa_required: bool = True
    mfa_token: str
    expires_in: int
    methods: list[str] = Field(default_factory=lambda: ["totp", "recovery_code"])


class MfaVerifyRequest(RequestModel):
    mfa_token: OpaqueToken
    code: SecondFactorCode


class MfaSetupRequest(RequestModel):
    password: Password


class MfaSetupResponse(ResponseModel):
    secret: str
    otpauth_uri: str


class MfaCodeRequest(RequestModel):
    code: SecondFactorCode


class MfaDisableRequest(RequestModel):
    password: Password
    code: SecondFactorCode


class MfaRecoveryCodesResponse(ResponseModel):
    recovery_codes: list[str]
    detail: str


class MfaStatusResponse(ResponseModel):
    enabled: bool
    enrollment_required: bool
    recovery_codes_remaining: int


class MeResponse(ResponseModel):
    user_id: uuid.UUID
    display_name: str
    role: Role
    customer_id: uuid.UUID | None
    permissions: list[str]
    mfa_enabled: bool
    mfa_enrollment_required: bool


class PasswordChangeRequest(RequestModel):
    current_password: Password
    new_password: Password


class PasswordResetRequest(RequestModel):
    email: EmailStr = Field(max_length=254)


class PasswordResetConfirm(RequestModel):
    token: OpaqueToken
    new_password: Password


class LogoutAllResponse(ResponseModel):
    revoked_sessions: int
