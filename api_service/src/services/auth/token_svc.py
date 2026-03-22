from __future__ import annotations

import json
from datetime import datetime
from time import time
from typing import Any, cast
from uuid import UUID, uuid4

from msgspec import json as msgjson

from src.models.auth.auth import IssuedToken, TokenBundle, TokenVerificationResult
from src.models.auth.auth import IdentityContext, Principal, TokenClaims, TokenRecord
from src.models.auth.auth_contract import (
    TokenRefreshRequest,
    TokenRevokeRequest,
    TokenVerifyRequest,
)
from src.repo.mysql_client import MySQLClient
from src.repo.redis_store import RedisManager


NIL_UUID = UUID(int=0)


class TokenService:
    """令牌签发、刷新和校验服务。"""

    def __init__(
        self,
        redis_manager: RedisManager | None = None,
        mysql_client: MySQLClient | None = None,
    ):
        self._access_token: IssuedToken | None = None
        self._refresh_token: IssuedToken | None = None
        self._revoked_token_ids: set[UUID] = set()
        self._revoked_family_ids: set[UUID] = set()
        self._redis_manager = redis_manager
        self._mysql_client = mysql_client

    def _latest_token_key(self, token_type: str) -> str:
        return f"auth:token:{token_type}:latest"

    def _revoked_token_key(self, token_id: UUID) -> str:
        return f"auth:token:revoked:id:{token_id}"

    def _revoked_family_key(self, family_id: UUID) -> str:
        return f"auth:token:revoked:family:{family_id}"

    async def _cache_token(self, token: IssuedToken) -> None:
        if self._redis_manager is None:
            return
        redis = self._redis_manager.get_client()
        ttl = max(int(token.claims.expires_at - time()), max(token.ttl_sec, 1))
        await redis.set(self._latest_token_key(token.type), msgjson.encode(token), ex=ttl)

    async def _load_cached_token(self, token_type: str) -> IssuedToken | None:
        if self._redis_manager is None:
            return None
        redis = self._redis_manager.get_client()
        raw = await redis.get(self._latest_token_key(token_type))
        if not raw:
            return None
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        return msgjson.decode(raw, type=IssuedToken)

    async def _cache_revocation(self, token_id: UUID, family_id: UUID) -> None:
        if self._redis_manager is None:
            return
        redis = self._redis_manager.get_client()
        if token_id != NIL_UUID:
            await redis.set(self._revoked_token_key(token_id), "1", ex=24 * 3600)
        if family_id != NIL_UUID:
            await redis.set(self._revoked_family_key(family_id), "1", ex=24 * 3600)

    async def _load_revocation(self, token_id: UUID, family_id: UUID) -> tuple[bool, bool]:
        if self._redis_manager is None:
            return False, False
        redis = self._redis_manager.get_client()
        token_revoked = False
        family_revoked = False
        if token_id != NIL_UUID:
            token_revoked = bool(await redis.get(self._revoked_token_key(token_id)))
        if family_id != NIL_UUID:
            family_revoked = bool(await redis.get(self._revoked_family_key(family_id)))
        return token_revoked, family_revoked

    async def _persist_refresh_token(self, token: IssuedToken) -> None:
        if self._mysql_client is None or token.type != "refresh":
            return
        claims = token.claims
        scope_json = json.dumps(claims.scopes, ensure_ascii=False)
        issued_at_dt = datetime.fromtimestamp(claims.issued_at)
        expires_at_dt = datetime.fromtimestamp(claims.expires_at)

        async with self._mysql_client.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO auth_token_records(
                    id, raw_token, family_id, session_id, token_type, status, storage,
                    principal_type, principal_id, parent_token_id, client_id, gateway_id,
                    role_snapshot, scope_snapshot, issued_at, expires_at, last_validated_at, revoked_at
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON DUPLICATE KEY UPDATE
                    status=VALUES(status), storage=VALUES(storage), parent_token_id=VALUES(parent_token_id),
                    client_id=VALUES(client_id), gateway_id=VALUES(gateway_id), role_snapshot=VALUES(role_snapshot),
                    scope_snapshot=VALUES(scope_snapshot), issued_at=VALUES(issued_at), expires_at=VALUES(expires_at),
                    last_validated_at=VALUES(last_validated_at), revoked_at=VALUES(revoked_at)
                """,
                (
                    str(claims.token_id),
                    token.raw,
                    str(claims.family_id),
                    str(claims.session_id),
                    token.type,
                    "active",
                    token.storage,
                    claims.entity_type,
                    claims.principal_id,
                    None if claims.parent_id == NIL_UUID else str(claims.parent_id),
                    claims.client_id,
                    claims.gateway_id,
                    claims.role,
                    scope_json,
                    issued_at_dt,
                    expires_at_dt,
                    issued_at_dt,
                    None,
                ),
            )
            await cur.execute(
                """
                INSERT INTO auth_token_claims(
                    token_id, issuer, audience, subject, token_type, entity_type, entity_id, principal_id,
                    session_id, family_id, parent_id, role, scopes, auth_method, client_id, gateway_id,
                    source_service, target_service, issued_at, expires_at
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON DUPLICATE KEY UPDATE
                    issuer=VALUES(issuer), audience=VALUES(audience), subject=VALUES(subject),
                    entity_type=VALUES(entity_type), entity_id=VALUES(entity_id), principal_id=VALUES(principal_id),
                    session_id=VALUES(session_id), family_id=VALUES(family_id), parent_id=VALUES(parent_id),
                    role=VALUES(role), scopes=VALUES(scopes), auth_method=VALUES(auth_method),
                    client_id=VALUES(client_id), gateway_id=VALUES(gateway_id),
                    source_service=VALUES(source_service), target_service=VALUES(target_service),
                    issued_at=VALUES(issued_at), expires_at=VALUES(expires_at)
                """,
                (
                    str(claims.token_id),
                    claims.issuer,
                    claims.audience,
                    claims.subject,
                    claims.type,
                    claims.entity_type,
                    claims.entity_id,
                    claims.principal_id,
                    str(claims.session_id),
                    str(claims.family_id),
                    None if claims.parent_id == NIL_UUID else str(claims.parent_id),
                    claims.role,
                    scope_json,
                    claims.auth_method,
                    claims.client_id,
                    claims.gateway_id,
                    claims.source_service,
                    claims.target_service,
                    issued_at_dt,
                    expires_at_dt,
                ),
            )
            conn = cast(Any, cur.connection)
            if conn is not None:
                await conn.commit()

    async def _load_refresh_from_db(self, raw_token: str | None = None) -> IssuedToken | None:
        if self._mysql_client is None:
            return None

        where_clause = "r.token_type = %s"
        params: list[object] = ["refresh"]
        if raw_token:
            where_clause += " AND r.raw_token = %s"
            params.append(raw_token)

        async with self._mysql_client.cursor() as cur:
            await cur.execute(
                f"""
                SELECT
                    r.id, r.raw_token, r.family_id, r.session_id, r.token_type, r.storage,
                    r.principal_type, r.principal_id, r.parent_token_id, r.client_id, r.gateway_id,
                    r.role_snapshot, r.scope_snapshot, r.issued_at, r.expires_at,
                    c.issuer, c.audience, c.subject, c.entity_type, c.entity_id,
                    c.scopes, c.auth_method, c.source_service, c.target_service, c.parent_id
                FROM auth_token_records r
                LEFT JOIN auth_token_claims c ON c.token_id = r.id
                WHERE {where_clause}
                ORDER BY r.issued_at DESC
                LIMIT 1
                """,
                tuple(params),
            )
            row = await cur.fetchone()

        if not row:
            return None

        scope_snapshot_raw = row.get("scope_snapshot") or row.get("scopes") or "[]"
        if isinstance(scope_snapshot_raw, (bytes, bytearray)):
            scope_snapshot_raw = scope_snapshot_raw.decode("utf-8")
        scopes = json.loads(scope_snapshot_raw) if isinstance(scope_snapshot_raw, str) else list(scope_snapshot_raw)

        principal_id = str(row.get("principal_id") or "")
        entity_type = cast(str, row.get("entity_type") or row.get("principal_type") or "service")
        entity_id = str(row.get("entity_id") or principal_id.split(":")[-1] if principal_id else "")

        token_id = UUID(str(row["id"]))
        family_id = UUID(str(row["family_id"]))
        session_id = UUID(str(row["session_id"]))
        parent_id_raw = row.get("parent_id") or row.get("parent_token_id")
        parent_id = UUID(str(parent_id_raw)) if parent_id_raw else NIL_UUID

        issued_at_dt = row["issued_at"]
        expires_at_dt = row["expires_at"]
        issued_at = issued_at_dt.timestamp() if hasattr(issued_at_dt, "timestamp") else float(issued_at_dt)
        expires_at = expires_at_dt.timestamp() if hasattr(expires_at_dt, "timestamp") else float(expires_at_dt)

        claims = TokenClaims(
            issuer=str(row.get("issuer") or "api_service"),
            audience=str(row.get("audience") or "internal"),
            subject=str(row.get("subject") or entity_id),
            type="refresh",
            entity_type=cast(Any, entity_type),
            entity_id=entity_id,
            principal_id=principal_id,
            session_id=session_id,
            token_id=token_id,
            family_id=family_id,
            parent_id=parent_id,
            role=str(row.get("role_snapshot") or ""),
            scopes=list(scopes),
            auth_method=cast(Any, str(row.get("auth_method") or "refresh_token")),
            client_id=str(row.get("client_id") or ""),
            gateway_id=str(row.get("gateway_id") or ""),
            source_service=str(row.get("source_service") or ""),
            target_service=str(row.get("target_service") or ""),
            issued_at=issued_at,
            expires_at=expires_at,
        )
        ttl = max(int(expires_at - time()), 1)
        return IssuedToken(
            raw=str(row["raw_token"]),
            type="refresh",
            storage="database",
            claims=claims,
            ttl_sec=ttl,
        )

    def set_bootstrap_tokens(self, bundle: TokenBundle | None) -> None:
        if bundle is None:
            return
        if bundle.access_token is not None:
            self._access_token = bundle.access_token
        if bundle.refresh_token is not None:
            self._refresh_token = bundle.refresh_token

    async def set_bootstrap_tokens_async(self, bundle: TokenBundle | None) -> None:
        self.set_bootstrap_tokens(bundle)
        if bundle is None:
            return
        if bundle.access_token is not None:
            await self._cache_token(bundle.access_token)
        if bundle.refresh_token is not None:
            await self._cache_token(bundle.refresh_token)
            await self._persist_refresh_token(bundle.refresh_token)

    async def get_access_token(self) -> IssuedToken | None:
        if self._access_token and time() < self._access_token.claims.expires_at:
            return self._access_token
        if self._access_token is None:
            self._access_token = await self._load_cached_token("access")
            if self._access_token and time() < self._access_token.claims.expires_at:
                return self._access_token
        if self._refresh_token is None:
            self._refresh_token = await self._load_cached_token("refresh")
        if self._refresh_token is None:
            self._refresh_token = await self._load_refresh_from_db()
        if self._refresh_token is None:
            return None
        refreshed = await self.refresh(
            TokenRefreshRequest(
                refresh_token=self._refresh_token.raw,
                client_id=self._refresh_token.claims.client_id,
                gateway_id=self._refresh_token.claims.gateway_id,
                source_ip="",
                user_agent="",
                request_id="",
                trace_id="",
            )
        )
        return refreshed.access_token if refreshed else None

    async def refresh(self, req: TokenRefreshRequest) -> TokenBundle | None:
        if self._refresh_token is None or self._refresh_token.raw != req.refresh_token:
            cached_refresh = await self._load_cached_token("refresh")
            if cached_refresh and cached_refresh.raw == req.refresh_token:
                self._refresh_token = cached_refresh
            else:
                self._refresh_token = await self._load_refresh_from_db(req.refresh_token)
        if self._refresh_token is None:
            return None
        if time() >= self._refresh_token.claims.expires_at:
            return None
        if self._refresh_token.claims.token_id in self._revoked_token_ids:
            return None
        if self._refresh_token.claims.family_id in self._revoked_family_ids:
            return None

        now = time()
        family_id = self._refresh_token.claims.family_id
        principal = Principal(
            entity_type=self._refresh_token.claims.entity_type,
            entity_id=self._refresh_token.claims.entity_id,
        )

        access_claims = TokenClaims(
            issuer="api_service",
            audience=self._refresh_token.claims.audience,
            subject=self._refresh_token.claims.subject,
            type="access",
            entity_type=principal.entity_type,
            entity_id=principal.entity_id,
            principal_id=principal.principal_id(),
            session_id=self._refresh_token.claims.session_id,
            token_id=uuid4(),
            family_id=family_id,
            parent_id=self._refresh_token.claims.token_id,
            role=self._refresh_token.claims.role,
            scopes=list(self._refresh_token.claims.scopes),
            auth_method="refresh_token",
            client_id=req.client_id,
            gateway_id=req.gateway_id,
            source_service=self._refresh_token.claims.source_service,
            target_service=self._refresh_token.claims.target_service,
            issued_at=now,
            expires_at=now + 300,
        )
        refresh_claims = TokenClaims(
            issuer="api_service",
            audience=self._refresh_token.claims.audience,
            subject=self._refresh_token.claims.subject,
            type="refresh",
            entity_type=principal.entity_type,
            entity_id=principal.entity_id,
            principal_id=principal.principal_id(),
            session_id=self._refresh_token.claims.session_id,
            token_id=uuid4(),
            family_id=family_id,
            parent_id=self._refresh_token.claims.token_id,
            role=self._refresh_token.claims.role,
            scopes=list(self._refresh_token.claims.scopes),
            auth_method="refresh_token",
            client_id=req.client_id,
            gateway_id=req.gateway_id,
            source_service=self._refresh_token.claims.source_service,
            target_service=self._refresh_token.claims.target_service,
            issued_at=now,
            expires_at=now + 86400,
        )

        new_access = IssuedToken(
            raw=f"access.{access_claims.token_id}",
            type="access",
            storage="cache",
            claims=access_claims,
            ttl_sec=300,
        )
        new_refresh = IssuedToken(
            raw=f"refresh.{refresh_claims.token_id}",
            type="refresh",
            storage="database",
            claims=refresh_claims,
            ttl_sec=86400,
        )

        self._revoked_token_ids.add(self._refresh_token.claims.token_id)
        self._access_token = new_access
        self._refresh_token = new_refresh
        await self._cache_token(new_access)
        await self._cache_token(new_refresh)
        await self._cache_revocation(access_claims.parent_id, family_id)
        await self._persist_refresh_token(new_refresh)
        return TokenBundle(access_token=new_access, refresh_token=new_refresh)

    async def verify(
        self, req: TokenVerifyRequest
    ) -> TokenVerificationResult | None:
        token = None
        if self._access_token and req.raw_token == self._access_token.raw:
            token = self._access_token
        elif self._refresh_token and req.raw_token == self._refresh_token.raw:
            token = self._refresh_token
        elif req.raw_token.startswith("access."):
            cached = await self._load_cached_token("access")
            if cached and cached.raw == req.raw_token:
                token = cached
        elif req.raw_token.startswith("refresh."):
            cached = await self._load_cached_token("refresh")
            if cached and cached.raw == req.raw_token:
                token = cached
            if token is None:
                token = await self._load_refresh_from_db(req.raw_token)

        if token is None:
            return TokenVerificationResult(
                valid=False,
                status="expired",
                failure_reason="token not found",
            )

        claims = token.claims
        revoked_token = claims.token_id in self._revoked_token_ids
        revoked_family = claims.family_id in self._revoked_family_ids
        if not revoked_token and not revoked_family:
            redis_revoked_token, redis_revoked_family = await self._load_revocation(
                claims.token_id,
                claims.family_id,
            )
            revoked_token = redis_revoked_token
            revoked_family = redis_revoked_family
        if revoked_token or revoked_family:
            return TokenVerificationResult(
                valid=False,
                status="revoked",
                failure_reason="token revoked",
            )
        if time() > claims.expires_at + max(req.allow_expired_skew_sec, 0):
            return TokenVerificationResult(
                valid=False,
                status="expired",
                failure_reason="token expired",
            )
        if req.expected_types and claims.type not in req.expected_types:
            return TokenVerificationResult(
                valid=False,
                status="revoked",
                failure_reason="unexpected token type",
            )

        identity = IdentityContext(
            principal=Principal(entity_type=claims.entity_type, entity_id=claims.entity_id),
            entity_type=claims.entity_type,
            entity_id=claims.entity_id,
            principal_id=claims.principal_id,
            session_id=claims.session_id,
            token_id=claims.token_id,
            token_family_id=claims.family_id,
            token_type=claims.type,
            role=claims.role,
            scopes=list(claims.scopes),
            auth_method=claims.auth_method,
            source_ip="",
            client_id=claims.client_id,
            gateway_id=claims.gateway_id,
            source_service=claims.source_service,
            target_service=claims.target_service,
            user_agent="",
            request_id="",
            trace_id="",
            secure_channel_id=NIL_UUID,
            secure_channel_status="",
            cipher_suite="",
            issued_at=claims.issued_at,
            expires_at=claims.expires_at,
        )
        record = TokenRecord(
            id=claims.token_id,
            family_id=claims.family_id,
            session_id=claims.session_id,
            type=claims.type,
            status="active",
            storage=token.storage,
            principal=identity.principal,
            principal_id=identity.principal_id,
            parent_token_id=claims.parent_id,
            client_id=claims.client_id,
            gateway_id=claims.gateway_id,
            role_snapshot=claims.role,
            scope_snapshot=list(claims.scopes),
            issued_at=claims.issued_at,
            expires_at=claims.expires_at,
            last_validated_at=time(),
            revoked_at=0.0,
        )
        return TokenVerificationResult(
            valid=True,
            status="active",
            identity=identity,
            token=record,
            failure_reason="",
        )

    async def revoke(self, req: TokenRevokeRequest) -> None:
        if req.token_id != NIL_UUID:
            self._revoked_token_ids.add(req.token_id)
        if req.family_id != NIL_UUID:
            self._revoked_family_ids.add(req.family_id)
        await self._cache_revocation(req.token_id, req.family_id)
