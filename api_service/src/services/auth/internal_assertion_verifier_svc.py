from __future__ import annotations

import base64
import hashlib
import time
from collections.abc import Mapping

from msgspec import DecodeError, json as msgjson

from src.models.auth.internal_assertion import (
    InternalAssertionClaims,
    InternalAssertionHeader,
    InternalAssertionVerifyRequest,
    VerifiedInternalIdentity,
)
from src.models.commsec.commsec import PublicKeyLookupRequest
from src.models.sys.config import InternalAssertionConfig
from src.repo.redis_store import RedisManager
from src.services.auth.runtime_metrics import AuthRuntimeMetrics
from src.services.commsec.secret_key_svc import SecretKeyService
from src.utils.crypto_utils import CryptoUtils


class InternalAssertionVerifier:
    """内部断言验证服务。"""

    def __init__(
        self,
        secret_key_service: SecretKeyService,
        redis_manager: RedisManager | None = None,
        service_name: str = "api_service",
        config: InternalAssertionConfig | None = None,
        crypto_utils: CryptoUtils | None = None,
        runtime_metrics: AuthRuntimeMetrics | None = None,
    ):
        self._secret_key_service = secret_key_service
        self._redis_manager = redis_manager
        self._service_name = service_name
        self._config = (config or InternalAssertionConfig()).normalized()
        self._crypto = crypto_utils or CryptoUtils()
        self._runtime_metrics = runtime_metrics

        # Redis 不可用时的开发兜底重放防护。
        self._seen_jti: dict[str, int] = {}

    @property
    def config(self) -> InternalAssertionConfig:
        return self._config

    async def verify_request(
        self,
        req: InternalAssertionVerifyRequest,
    ) -> VerifiedInternalIdentity:
        if self._runtime_metrics is not None:
            self._runtime_metrics.record_assertion_attempt()

        try:
            assertion = _get_header_value(req.headers, self._config.header_name)
            if not assertion:
                raise ValueError("internal assertion is missing")

            header, claims, signing_input, signature_segment = _parse_assertion(
                assertion
            )

            self._validate_claims(
                claims=claims,
                method=req.method,
                path=req.path,
                query=req.query,
                body=req.body,
            )

            public_key_pem = await self._resolve_public_key_pem(
                header=header, claims=claims
            )
            signature_std = _signature_segment_to_standard_b64(signature_segment)
            self._crypto.verify_by_algorithm(
                header.alg,
                signing_input.encode("utf-8"),
                signature_std,
                public_key_pem,
            )

            await self._ensure_not_replayed(claims)

            if self._runtime_metrics is not None:
                self._runtime_metrics.record_assertion_success()

            return VerifiedInternalIdentity(
                principal_id=claims.principal_id,
                entity_type=claims.entity_type,
                entity_id=claims.entity_id,
                session_id=claims.session_id,
                token_id=claims.token_id,
                gateway_id=claims.gateway_id,
                source_service=claims.iss,
                target_service=claims.aud,
                trace_id=claims.trace_id,
                request_id=claims.request_id,
                scopes=list(claims.scopes),
                jti=claims.jti,
                key_id=header.kid,
            )
        except Exception as exc:  # noqa: BLE001
            if self._runtime_metrics is not None:
                self._runtime_metrics.record_assertion_failure()
                if "replay detected" in str(exc).lower():
                    self._runtime_metrics.record_assertion_replay_hit()
            raise

    def _validate_claims(
        self,
        claims: InternalAssertionClaims,
        method: str,
        path: str,
        query: dict[str, str],
        body: bytes,
    ) -> None:
        now = int(time.time())
        skew = self._config.clock_skew_sec

        if claims.aud != self._service_name:
            raise ValueError(
                f"internal assertion audience mismatch: expected {self._service_name}, got {claims.aud}"
            )

        if claims.iat > now + skew:
            raise ValueError("internal assertion iat is in the future")
        if claims.exp < now - skew:
            raise ValueError("internal assertion is expired")

        normalized_method = method.strip()
        if claims.method and normalized_method and claims.method != normalized_method:
            raise ValueError("internal assertion method mismatch")

        if self._config.enforce_path_binding and claims.path:
            if not path:
                raise ValueError("request path is missing for assertion path binding")
            if claims.path != path:
                raise ValueError("internal assertion path mismatch")

        if claims.query_hash:
            expected_query_hash = _hash_query(query)
            if expected_query_hash != claims.query_hash:
                raise ValueError("internal assertion query hash mismatch")

        if claims.body_sha256:
            expected_body_hash = _hash_bytes(body)
            if expected_body_hash != claims.body_sha256:
                raise ValueError("internal assertion body hash mismatch")

    async def _resolve_public_key_pem(
        self,
        header: InternalAssertionHeader,
        claims: InternalAssertionClaims,
    ) -> bytes:
        lookup = await self._secret_key_service.lookup_public_key(
            PublicKeyLookupRequest(
                key_id=header.kid,
                entity_id=claims.iss or "",
                require_active=True,
            )
        )

        if not lookup.found or lookup.key is None:
            raise ValueError("public key for internal assertion is not found")

        key = lookup.key
        if key.status != "active":
            raise ValueError("public key for internal assertion is not active")

        return key.public_key_pem.encode("utf-8")

    async def _ensure_not_replayed(self, claims: InternalAssertionClaims) -> None:
        now = int(time.time())
        ttl = max(
            claims.exp - now + self._config.clock_skew_sec,
            self._config.replay_ttl_sec,
            1,
        )
        replay_key = f"internal_assertion:jti:{claims.jti}"

        if self._redis_manager is not None:
            try:
                client = self._redis_manager.get_client()
                marked = await client.set(replay_key, "1", ex=ttl, nx=True)
                if not marked:
                    raise ValueError("internal assertion replay detected")
                return
            except RuntimeError:
                # Redis 未初始化时降级为内存保护。
                pass

        self._evict_expired_jti(now)
        cached_expire_at = self._seen_jti.get(claims.jti)
        if cached_expire_at and cached_expire_at > now:
            raise ValueError("internal assertion replay detected")
        self._seen_jti[claims.jti] = now + ttl

    def _evict_expired_jti(self, now: int) -> None:
        expired = [jti for jti, expire_at in self._seen_jti.items() if expire_at <= now]
        for jti in expired:
            self._seen_jti.pop(jti, None)


def _parse_assertion(
    assertion: str,
) -> tuple[InternalAssertionHeader, InternalAssertionClaims, str, str]:
    parts = assertion.split(".")
    if len(parts) != 3:
        raise ValueError("internal assertion format is invalid")

    header_segment, payload_segment, signature_segment = parts

    try:
        header_raw = _decode_b64url_segment(header_segment)
        payload_raw = _decode_b64url_segment(payload_segment)
    except Exception as exc:  # noqa: BLE001
        raise ValueError("internal assertion segment decode failed") from exc

    try:
        header = msgjson.decode(header_raw, type=InternalAssertionHeader)
        claims = msgjson.decode(payload_raw, type=InternalAssertionClaims)
    except DecodeError as exc:
        raise ValueError("internal assertion payload decode failed") from exc

    if not header.alg or not header.kid:
        raise ValueError("internal assertion header is incomplete")
    if not claims.iss or not claims.aud or not claims.jti:
        raise ValueError("internal assertion claims are incomplete")

    signing_input = header_segment + "." + payload_segment
    return header, claims, signing_input, signature_segment


def _decode_b64url_segment(segment: str) -> bytes:
    padded = segment + ("=" * (-len(segment) % 4))
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _signature_segment_to_standard_b64(signature_segment: str) -> str:
    signature_raw = _decode_b64url_segment(signature_segment)
    return base64.b64encode(signature_raw).decode("ascii")


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash_query(query: Mapping[str, str]) -> str:
    if not query:
        return ""

    normalized = "".join(f"{k}={query[k]}\n" for k in sorted(query.keys()))
    return _hash_bytes(normalized.encode("utf-8"))


def _get_header_value(headers: Mapping[str, str], key: str) -> str:
    if not headers:
        return ""

    exact = headers.get(key)
    if exact:
        return exact

    lower_key = key.lower()
    for hk, hv in headers.items():
        if hk.lower() == lower_key and hv:
            return hv

    return ""
