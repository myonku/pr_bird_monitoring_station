from __future__ import annotations

from time import time
from typing import cast
from uuid import UUID, uuid4

from msgspec import json as msgjson

from src.models.auth.auth import (
    IdentityContext,
    IssuedToken,
    Principal,
    Session,
    TokenBundle,
    TokenClaims,
)
from src.models.auth.bootstrap import (
    BootstrapAuthRequest,
    BootstrapAuthResult,
    BootstrapStage,
    ChallengePayload,
    ChallengeRequest,
)
from src.repo.redis_store import RedisManager


NIL_UUID = UUID(int=0)


class BootstrapClient:
    """冷启动认证流程服务（内存模拟）。"""

    def __init__(self, issuer: str = "certification_server", redis_manager: RedisManager | None = None):
        self.issuer = issuer
        self._redis_manager = redis_manager
        self._challenges: dict[UUID, ChallengePayload] = {}
        self._stages: dict[str, BootstrapStage] = {}

    def _challenge_key(self, challenge_id: UUID) -> str:
        return f"auth:bootstrap:challenge:{challenge_id}"

    def _stage_key(self, principal_id: str) -> str:
        return f"auth:bootstrap:stage:{principal_id}"

    async def _cache_challenge(self, payload: ChallengePayload) -> None:
        if self._redis_manager is None:
            return
        redis = self._redis_manager.get_client()
        ttl = max(int(payload.expires_at - time()), 5)
        await redis.set(self._challenge_key(payload.challenge_id), msgjson.encode(payload), ex=ttl)

    async def _load_challenge(self, challenge_id: UUID) -> ChallengePayload | None:
        if self._redis_manager is None:
            return None
        redis = self._redis_manager.get_client()
        raw = await redis.get(self._challenge_key(challenge_id))
        if not raw:
            return None
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        return msgjson.decode(raw, type=ChallengePayload)

    async def _cache_stage(self, principal_id: str, stage: BootstrapStage) -> None:
        if self._redis_manager is None:
            return
        redis = self._redis_manager.get_client()
        await redis.set(self._stage_key(principal_id), stage, ex=24 * 3600)
        await redis.set("auth:bootstrap:stage:last", stage, ex=24 * 3600)
        await redis.set("auth:bootstrap:stage:last_principal", principal_id, ex=24 * 3600)

    async def _load_stage(self, principal_id: str) -> BootstrapStage | None:
        if self._redis_manager is None:
            return None
        redis = self._redis_manager.get_client()
        raw = await redis.get(self._stage_key(principal_id))
        if not raw:
            return None
        return cast(BootstrapStage, str(raw))

    async def init_challenge(self, req: ChallengeRequest) -> ChallengePayload:
        if not req.entity_id or not req.key_id:
            raise ValueError("entity_id and key_id are required")

        now = time()
        ttl = req.ttl_sec if req.ttl_sec > 0 else 120
        payload = ChallengePayload(
            challenge_id=uuid4(),
            issuer=self.issuer,
            audience=req.audience,
            entity_type=req.entity_type,
            entity_id=req.entity_id,
            key_id=req.key_id,
            nonce=uuid4().hex,
            issued_at=now,
            expires_at=now + ttl,
        )
        principal_id = Principal(
            entity_type=req.entity_type,
            entity_id=req.entity_id,
        ).principal_id()
        self._challenges[payload.challenge_id] = payload
        self._stages[principal_id] = "challenging"
        await self._cache_challenge(payload)
        await self._cache_stage(principal_id, "challenging")
        return payload

    async def authenticate_bootstrap(
        self, req: BootstrapAuthRequest
    ) -> BootstrapAuthResult:
        challenge = self._challenges.get(req.challenge.challenge_id)
        if challenge is None:
            challenge = await self._load_challenge(req.challenge.challenge_id)
        if challenge is None:
            raise ValueError("challenge not found")
        if time() > challenge.expires_at:
            raise ValueError("challenge expired")
        if req.signed.key_id != challenge.key_id:
            raise ValueError("challenge key mismatch")

        now = time()
        principal = Principal(
            entity_type=challenge.entity_type,
            entity_id=challenge.entity_id,
        )
        principal_id = principal.principal_id()

        session_id = uuid4()
        family_id = uuid4()
        access_token_id = uuid4()
        refresh_token_id = uuid4()

        session = Session(
            id=session_id,
            principal=principal,
            entity_type=principal.entity_type,
            entity_id=principal.entity_id,
            principal_id=principal_id,
            status="active",
            auth_method="service_secret",
            created_by_ip="",
            last_seen_ip="",
            user_agent="",
            client_id="",
            gateway_id="",
            scope_snapshot=list(req.scopes),
            role_snapshot=req.role,
            token_family_id=family_id,
            created_at=now,
            updated_at=now,
            last_seen_at=now,
            last_verified_at=0.0,
            next_refresh_at=now + 1800,
            expires_at=now + 86400,
            revoked_at=0.0,
            version=1,
        )

        access_claims = TokenClaims(
            issuer=self.issuer,
            audience=challenge.audience,
            subject=principal.entity_id,
            type="access",
            entity_type=principal.entity_type,
            entity_id=principal.entity_id,
            principal_id=principal_id,
            session_id=session_id,
            token_id=access_token_id,
            family_id=family_id,
            parent_id=NIL_UUID,
            role=req.role,
            scopes=list(req.scopes),
            auth_method="service_secret",
            client_id="",
            gateway_id="",
            source_service="",
            target_service="",
            issued_at=now,
            expires_at=now + 600,
        )
        refresh_claims = TokenClaims(
            issuer=self.issuer,
            audience=challenge.audience,
            subject=principal.entity_id,
            type="refresh",
            entity_type=principal.entity_type,
            entity_id=principal.entity_id,
            principal_id=principal_id,
            session_id=session_id,
            token_id=refresh_token_id,
            family_id=family_id,
            parent_id=access_token_id,
            role=req.role,
            scopes=list(req.scopes),
            auth_method="service_secret",
            client_id="",
            gateway_id="",
            source_service="",
            target_service="",
            issued_at=now,
            expires_at=now + 86400,
        )

        tokens = TokenBundle(
            access_token=IssuedToken(
                raw=f"access.{access_token_id}",
                type="access",
                storage="cache",
                claims=access_claims,
                ttl_sec=600,
            ),
            refresh_token=IssuedToken(
                raw=f"refresh.{refresh_token_id}",
                type="refresh",
                storage="database",
                claims=refresh_claims,
                ttl_sec=86400,
            ),
        )

        identity = IdentityContext(
            principal=principal,
            entity_type=principal.entity_type,
            entity_id=principal.entity_id,
            principal_id=principal_id,
            session_id=session_id,
            token_id=access_token_id,
            token_family_id=family_id,
            token_type="access",
            role=req.role,
            scopes=list(req.scopes),
            auth_method="service_secret",
            source_ip="",
            client_id="",
            gateway_id="",
            source_service="",
            target_service="",
            user_agent="",
            request_id="",
            trace_id="",
            secure_channel_id=NIL_UUID,
            secure_channel_status="",
            cipher_suite="",
            issued_at=now,
            expires_at=access_claims.expires_at,
        )

        self._stages[principal_id] = "ready"
        self._challenges.pop(challenge.challenge_id, None)
        if self._redis_manager is not None:
            redis = self._redis_manager.get_client()
            await redis.delete(self._challenge_key(challenge.challenge_id))
        await self._cache_stage(principal_id, "ready")
        return BootstrapAuthResult(
            stage="ready",
            identity=identity,
            session=session,
            tokens=tokens,
            active_comm_key_id=challenge.key_id,
            issued_at=now,
            expires_at=access_claims.expires_at,
        )

    async def get_bootstrap_stage(self, ctx: object) -> BootstrapStage:
        principal_id = ""
        if isinstance(ctx, dict):
            principal_id = str(ctx.get("principal_id") or "")
        if principal_id:
            stage = self._stages.get(principal_id)
            if stage:
                return stage
            cached = await self._load_stage(principal_id)
            return cached or "uninitialized"
        if self._stages:
            return next(iter(self._stages.values()))
        if self._redis_manager is not None:
            redis = self._redis_manager.get_client()
            last = await redis.get("auth:bootstrap:stage:last")
            if last:
                return cast(BootstrapStage, str(last))
        return "uninitialized"
