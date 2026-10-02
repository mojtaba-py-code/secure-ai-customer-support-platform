"""Authentication endpoints."""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, Request, Response, status

from aegis.api.deps import ClientIpDep, ContainerDep, PrincipalDep, ServicesDep, enforce_rate_limit
from aegis.api.v1 import API_V1_PREFIX
from aegis.core.time import utc_now
from aegis.schemas.auth import (
    LoginRequest,
    LogoutAllResponse,
    MeResponse,
    MfaChallengeResponse,
    MfaCodeRequest,
    MfaDisableRequest,
    MfaRecoveryCodesResponse,
    MfaSetupRequest,
    MfaSetupResponse,
    MfaStatusResponse,
    MfaVerifyRequest,
    PasswordChangeRequest,
    PasswordResetConfirm,
    PasswordResetRequest,
    RefreshRequest,
    TokenResponse,
)
from aegis.schemas.common import Message
from aegis.security.crypto import fingerprint
from aegis.security.rbac import ROLE_PERMISSIONS
from aegis.services.auth import MfaChallengeIssued, TokenPair
from aegis.services.email import EmailSender, OutgoingEmail

logger = logging.getLogger(__name__)
router = APIRouter(prefix=f"{API_V1_PREFIX}/auth", tags=["auth"])

RESET_ACCEPTED = "If the address belongs to an account, a password reset link has been sent."


def _token_response(pair: TokenPair) -> TokenResponse:
    return TokenResponse(
        access_token=pair.access_token,
        expires_in=max(0, int((pair.access_expires_at - utc_now()).total_seconds())),
        access_expires_at=pair.access_expires_at,
        refresh_token=pair.refresh_token,
        refresh_expires_at=pair.refresh_expires_at,
    )


async def _send_email(sender: EmailSender, message: OutgoingEmail) -> None:
    try:
        await sender.send(message)
    except Exception:  # delivery problems must not surface to the requester
        logger.exception("password reset e-mail failed", extra={"event": "email.failed"})


@router.post("/login", response_model=TokenResponse | MfaChallengeResponse)
async def login(
    body: LoginRequest,
    request: Request,
    container: ContainerDep,
    services: ServicesDep,
    ip: ClientIpDep,
) -> TokenResponse | MfaChallengeResponse:
    """Sign in. Accounts with two-factor authentication get a challenge instead of tokens."""
    await enforce_rate_limit(container, container.rate_limits.login_ip, f"ip:{ip}")
    await enforce_rate_limit(
        container, container.rate_limits.login_account, f"acct:{fingerprint(body.email.lower())}"
    )
    result = await services.auth.login(
        body.email, body.password, ip=ip, user_agent=request.headers.get("user-agent")
    )
    if isinstance(result, MfaChallengeIssued):
        return MfaChallengeResponse(
            mfa_token=result.token,
            expires_in=max(0, int((result.expires_at - utc_now()).total_seconds())),
        )
    return _token_response(result)


@router.post("/mfa/verify", response_model=TokenResponse)
async def verify_mfa(
    body: MfaVerifyRequest,
    request: Request,
    container: ContainerDep,
    services: ServicesDep,
    ip: ClientIpDep,
) -> TokenResponse:
    """Second sign-in step: a code from the authenticator app, or a recovery code."""
    await enforce_rate_limit(container, container.rate_limits.login_ip, f"ip:{ip}")
    pair = await services.auth.verify_mfa(
        body.mfa_token, body.code, ip=ip, user_agent=request.headers.get("user-agent")
    )
    return _token_response(pair)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    body: RefreshRequest, container: ContainerDep, services: ServicesDep, ip: ClientIpDep
) -> TokenResponse:
    await enforce_rate_limit(container, container.rate_limits.refresh, f"ip:{ip}")
    return _token_response(await services.auth.refresh(body.refresh_token))


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(principal: PrincipalDep, services: ServicesDep) -> Response:
    await services.auth.logout(principal)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/logout-all", response_model=LogoutAllResponse)
async def logout_all(principal: PrincipalDep, services: ServicesDep) -> LogoutAllResponse:
    return LogoutAllResponse(revoked_sessions=await services.auth.logout_all(principal))


@router.get("/me", response_model=MeResponse)
async def me(principal: PrincipalDep) -> MeResponse:
    permissions = [p.value for p in ROLE_PERMISSIONS[principal.role] if principal.has(p)]
    return MeResponse(
        user_id=principal.user_id,
        display_name=principal.display_name,
        role=principal.role,
        customer_id=principal.customer_id,
        permissions=sorted(permissions),
        mfa_enabled=principal.mfa_enabled,
        mfa_enrollment_required=principal.mfa_enrollment_required,
    )


# --- two-factor authentication ----------------------------------------------------------------------
async def _limit_mfa_management(container: ContainerDep, principal: PrincipalDep) -> None:
    """Password and code checks below get the same per-account budget as the login form."""
    await enforce_rate_limit(
        container, container.rate_limits.login_account, f"mfa:{principal.user_id}"
    )


MfaManager = Annotated[None, Depends(_limit_mfa_management)]


@router.get("/mfa", response_model=MfaStatusResponse)
async def mfa_status(principal: PrincipalDep, services: ServicesDep) -> MfaStatusResponse:
    status_ = await services.mfa.status(principal)
    return MfaStatusResponse(
        enabled=status_.enabled,
        enrollment_required=status_.enrollment_required,
        recovery_codes_remaining=status_.recovery_codes_remaining,
    )


@router.post("/mfa/setup", response_model=MfaSetupResponse)
async def mfa_setup(
    body: MfaSetupRequest, principal: PrincipalDep, services: ServicesDep, _: MfaManager
) -> MfaSetupResponse:
    """Start enrolment: returns the secret once (add it to an authenticator app)."""
    setup = await services.mfa.begin_setup(principal, password=body.password)
    return MfaSetupResponse(secret=setup.secret, otpauth_uri=setup.otpauth_uri)


@router.post("/mfa/enable", response_model=MfaRecoveryCodesResponse)
async def mfa_enable(
    body: MfaCodeRequest, principal: PrincipalDep, services: ServicesDep, _: MfaManager
) -> MfaRecoveryCodesResponse:
    """Finish enrolment with a first code. Every session ends; sign in again with a code."""
    codes = await services.mfa.enable(principal, code=body.code)
    return MfaRecoveryCodesResponse(
        recovery_codes=codes,
        detail="Two-factor authentication is on. Store these recovery codes safely, then sign in again.",
    )


@router.post("/mfa/recovery-codes", response_model=MfaRecoveryCodesResponse)
async def mfa_recovery_codes(
    body: MfaCodeRequest, principal: PrincipalDep, services: ServicesDep, _: MfaManager
) -> MfaRecoveryCodesResponse:
    """Replace every recovery code (the old ones stop working)."""
    codes = await services.mfa.regenerate_recovery_codes(principal, code=body.code)
    return MfaRecoveryCodesResponse(
        recovery_codes=codes, detail="New recovery codes; the previous ones no longer work."
    )


@router.post("/mfa/disable", status_code=status.HTTP_204_NO_CONTENT)
async def mfa_disable(
    body: MfaDisableRequest, principal: PrincipalDep, services: ServicesDep, _: MfaManager
) -> Response:
    await services.mfa.disable(principal, password=body.password, code=body.code)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/password/change", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    body: PasswordChangeRequest, principal: PrincipalDep, services: ServicesDep
) -> Response:
    await services.auth.change_password(
        principal, current_password=body.current_password, new_password=body.new_password
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/password-reset/request", status_code=status.HTTP_202_ACCEPTED, response_model=Message
)
async def request_password_reset(
    body: PasswordResetRequest,
    background: BackgroundTasks,
    container: ContainerDep,
    services: ServicesDep,
    ip: ClientIpDep,
) -> Message:
    await enforce_rate_limit(container, container.rate_limits.password_reset, f"ip:{ip}")
    await enforce_rate_limit(
        container, container.rate_limits.password_reset, f"email:{fingerprint(body.email.lower())}"
    )
    email = await services.auth.request_password_reset(body.email)
    if email is not None:
        background.add_task(_send_email, container.email, email)
    return Message(detail=RESET_ACCEPTED)


@router.post("/password-reset/confirm", status_code=status.HTTP_204_NO_CONTENT)
async def confirm_password_reset(
    body: PasswordResetConfirm, container: ContainerDep, services: ServicesDep, ip: ClientIpDep
) -> Response:
    await enforce_rate_limit(container, container.rate_limits.password_reset, f"ip:{ip}")
    await services.auth.confirm_password_reset(body.token, body.new_password)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
