from __future__ import annotations

import asyncio
import inspect
from copy import deepcopy
from dataclasses import dataclass, field
from time import time
from typing import Awaitable, Callable, Protocol, cast
from uuid import UUID

from src.models.auth.auth import IdentityContext, Session, TokenBundle, TokenType
from src.models.auth.auth_contract import (
    SessionRevokeRequest,
    SessionValidateRequest,
    TokenRefreshRequest,
    TokenRevokeRequest,
    TokenVerifyRequest,
)
from src.models.auth.bootstrap import (
    BootstrapAuthRequest,
    BootstrapAuthResult,
    ChallengePayload,
    ChallengeRequest,
    SignedChallengeResponse,
)
from src.services.auth.auth_authority import IAuthAuthorityClient
from src.services.auth.bootstrap_cli import BootstrapClient

NIL_UUID = UUID(int=0)
DEFAULT_REFRESH_LEEWAY_SEC = 60

ChallengeSigner = Callable[
    [ChallengePayload],
    SignedChallengeResponse | Awaitable[SignedChallengeResponse],
]


@dataclass(slots=True)
class ModuleCredentialBootstrapConfig:
    challenge_request: ChallengeRequest
    role: str = "service"
    scopes: list[str] = field(default_factory=lambda: ["internal.invoke"])
    require_downstream_token: bool = False


class IModuleCredentialManager(Protocol):
    async def ensure_active(self) -> BootstrapAuthResult:
        ...

    def snapshot(self) -> BootstrapAuthResult | None:
        ...

    async def revoke(self, reason: str = "", revoked_by: str = "") -> None:
        ...


class ModuleCredentialManager:
    """普通服务模块本地凭证生命周期管理。"""

    def __init__(
        self,
        authority_client: IAuthAuthorityClient,
        bootstrap_client: BootstrapClient,
        bootstrap_config: ModuleCredentialBootstrapConfig,
        refresh_leeway_sec: int = DEFAULT_REFRESH_LEEWAY_SEC,
        challenge_signer: ChallengeSigner | None = None,
    ):
        self._authority_client = authority_client
        self._bootstrap_client = bootstrap_client
        self._bootstrap_config = bootstrap_config
        self._refresh_leeway_sec = max(int(refresh_leeway_sec), 0)
        self._challenge_signer = challenge_signer

        self._state: BootstrapAuthResult | None = None
        self._lock = asyncio.Lock()

    async def ensure_active(self) -> BootstrapAuthResult:
        async with self._lock:
            current = self._clone_state(self._state)
            if current is None or not _has_refresh_token(current.tokens):
                return await self._bootstrap_and_persist()

            refresh_token = _require_refresh_token(current.tokens)

            if not _should_refresh_access(current, self._refresh_leeway_sec):
                return current

            try:
                refreshed = await self._authority_client.refresh_module_token(
                    TokenRefreshRequest(
                        refresh_token=refresh_token,
                        client_id=_pick_client_id(current.identity),
                        gateway_id=_pick_gateway_id(
                            current.identity,
                            self._bootstrap_config.challenge_request.entity_id,
                        ),
                        source_ip="",
                        user_agent="",
                        request_id="",
                        trace_id="",
                    )
                )
            except Exception:
                return await self._bootstrap_and_persist()

            if refreshed is None:
                return await self._bootstrap_and_persist()

            merged = await self._merge_refreshed_state(current, refreshed)
            self._state = self._clone_state(merged)
            return merged

    def snapshot(self) -> BootstrapAuthResult | None:
        return self._clone_state(self._state)

    async def revoke(self, reason: str = "", revoked_by: str = "") -> None:
        async with self._lock:
            current = self._clone_state(self._state)
            self._state = None

        if current is None:
            return

        identity = current.identity
        session = current.session

        session_id = identity.session_id if identity is not None else NIL_UUID
        principal_id = identity.principal_id if identity is not None else ""
        if session_id == NIL_UUID and session is not None:
            session_id = session.id
            principal_id = principal_id or session.principal_id

        if session_id != NIL_UUID:
            await self._authority_client.revoke_module_session(
                SessionRevokeRequest(
                    session_id=session_id,
                    principal_id=principal_id,
                    reason=reason,
                    revoked_by=revoked_by,
                    request_id="",
                    trace_id="",
                )
            )

        family_id = identity.token_family_id if identity is not None else NIL_UUID
        token_id = identity.token_id if identity is not None else NIL_UUID
        if family_id == NIL_UUID and session is not None:
            family_id = session.token_family_id

        if family_id != NIL_UUID or token_id != NIL_UUID:
            await self._authority_client.revoke_token(
                TokenRevokeRequest(
                    token_id=token_id,
                    family_id=family_id,
                    session_id=session_id,
                    reason=reason,
                    revoked_by=revoked_by,
                    request_id="",
                    trace_id="",
                )
            )

    async def _bootstrap_and_persist(self) -> BootstrapAuthResult:
        challenge = await self._bootstrap_client.init_challenge(
            self._bootstrap_config.challenge_request
        )
        signed = await self._sign_challenge(challenge)

        result = await self._bootstrap_client.authenticate_bootstrap(
            BootstrapAuthRequest(
                challenge=challenge,
                signed=signed,
                role=self._bootstrap_config.role,
                scopes=list(self._bootstrap_config.scopes),
                require_downstream_token=self._bootstrap_config.require_downstream_token,
            )
        )

        if result is None or not _has_refresh_token(result.tokens):
            raise ValueError("module bootstrap did not return refresh token")

        hydrated = await self._hydrate_state(result)
        self._state = self._clone_state(hydrated)
        return hydrated

    async def _merge_refreshed_state(
        self,
        base: BootstrapAuthResult,
        refreshed: TokenBundle,
    ) -> BootstrapAuthResult:
        merged_tokens = _merge_token_bundle(base.tokens, refreshed)
        merged = BootstrapAuthResult(
            stage="ready",
            identity=base.identity,
            session=base.session,
            tokens=merged_tokens,
            active_comm_key_id=base.active_comm_key_id,
            issued_at=base.issued_at,
            expires_at=base.expires_at,
        )
        return await self._hydrate_state(merged)

    async def _hydrate_state(self, state: BootstrapAuthResult) -> BootstrapAuthResult:
        if state.tokens is None or state.tokens.access_token is None:
            raise ValueError("module credentials missing access token")

        verify_res = await self._authority_client.verify_token(
            TokenVerifyRequest(
                raw_token=state.tokens.access_token.raw,
                expected_types=cast(list[TokenType], ["access", "service"]),
                expected_audience="",
                require_scopes=[],
                source_service="",
                target_service="",
                allow_expired_skew_sec=0,
            )
        )
        if verify_res is None or not verify_res.valid or verify_res.identity is None:
            raise ValueError("module access token verification failed")

        identity = verify_res.identity
        if not identity.gateway_id:
            identity = _clone_identity(identity)
            identity.gateway_id = self._bootstrap_config.challenge_request.entity_id
        if not identity.source_service:
            identity = _clone_identity(identity)
            identity.source_service = identity.entity_id

        session: Session | None = state.session
        if identity.session_id != NIL_UUID:
            validated = await self._authority_client.validate_session(
                SessionValidateRequest(
                    session_id=identity.session_id,
                    principal_id=identity.principal_id,
                    require_active=True,
                    min_version=0,
                )
            )
            if validated is not None:
                session = validated

        access_claims = state.tokens.access_token.claims
        issued_at = access_claims.issued_at or state.issued_at or time()
        expires_at = access_claims.expires_at or identity.expires_at or state.expires_at

        return BootstrapAuthResult(
            stage="ready",
            identity=identity,
            session=session,
            tokens=state.tokens,
            active_comm_key_id=state.active_comm_key_id,
            issued_at=issued_at,
            expires_at=expires_at,
        )

    async def _sign_challenge(self, challenge: ChallengePayload) -> SignedChallengeResponse:
        if self._challenge_signer is None:
            return _default_signed_challenge(challenge)

        signed = self._challenge_signer(challenge)
        if inspect.isawaitable(signed):
            return await cast(Awaitable[SignedChallengeResponse], signed)
        return cast(SignedChallengeResponse, signed)

    @staticmethod
    def _clone_state(state: BootstrapAuthResult | None) -> BootstrapAuthResult | None:
        if state is None:
            return None
        return deepcopy(state)


def _default_signed_challenge(challenge: ChallengePayload) -> SignedChallengeResponse:
    return SignedChallengeResponse(
        challenge_id=challenge.challenge_id,
        key_id=challenge.key_id,
        signature_algorithm="ed25519",
        signature="memory-signed",
        signed_at=time(),
    )


def _has_refresh_token(tokens: TokenBundle | None) -> bool:
    return bool(tokens and tokens.refresh_token and tokens.refresh_token.raw)


def _require_refresh_token(tokens: TokenBundle | None) -> str:
    if tokens is None or tokens.refresh_token is None or not tokens.refresh_token.raw:
        raise ValueError("module credentials missing refresh token")
    return tokens.refresh_token.raw


def _should_refresh_access(state: BootstrapAuthResult, leeway_sec: int) -> bool:
    if state.tokens is None or state.tokens.access_token is None:
        return True

    expires_at = state.tokens.access_token.claims.expires_at or state.expires_at
    if expires_at <= 0:
        return True

    return expires_at <= time() + max(leeway_sec, 0)


def _merge_token_bundle(base: TokenBundle | None, refreshed: TokenBundle) -> TokenBundle:
    access_token = refreshed.access_token
    refresh_token = refreshed.refresh_token
    downstream_token = refreshed.downstream_token

    if base is not None:
        if access_token is None:
            access_token = base.access_token
        if refresh_token is None:
            refresh_token = base.refresh_token
        if downstream_token is None:
            downstream_token = base.downstream_token

    return TokenBundle(
        access_token=access_token,
        refresh_token=refresh_token,
        downstream_token=downstream_token,
    )


def _pick_client_id(identity: IdentityContext | None) -> str:
    if identity is None:
        return ""
    return identity.client_id or ""


def _pick_gateway_id(identity: IdentityContext | None, fallback_entity_id: str) -> str:
    if identity is not None and identity.gateway_id:
        return identity.gateway_id
    if identity is not None and identity.entity_id:
        return identity.entity_id
    return fallback_entity_id


def _clone_identity(identity: IdentityContext) -> IdentityContext:
    return deepcopy(identity)
