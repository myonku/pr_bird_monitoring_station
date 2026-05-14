from dataclasses import asdict
import json
from typing import cast
from urllib import request
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse

from src.iface.auth_interface import IEdgeGatewayAuthClient
from src.models.auth.auth import (
    AuthStage,
    EdgeSession,
    EdgeToken,
    EdgeTokenBundle,
    SessionStatus,
    TokenType,
)
from src.models.auth.auth_contract import EdgeAuthState, RefreshTokenRequest
from src.models.auth.bootstrap import (
    BootstrapAuthenticateRequest,
    BootstrapChallenge,
)
from src.orchestration.auth_coordinator import EdgeAuthCoordinator


class EdgeGatewayAuthHttpClient(IEdgeGatewayAuthClient):
    """边缘端到网关认证接口的 HTTP 客户端实现。"""

    def __init__(
        self,
        *,
        auth_base_url: str,
        auth_path: str = "/v1/edge/auth",
        timeout_sec: float = 3.0,
        default_audience: str = "gateway",
    ) -> None:
        base = auth_base_url.rstrip("/")
        if not base:
            raise ValueError("auth_base_url is required")

        parsed = urlparse(base)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"invalid auth_base_url: {auth_base_url}")

        self._base_url = base
        self._auth_path = self._normalize_path(auth_path)
        self._timeout_sec = max(0.1, float(timeout_sec))
        self._default_audience = default_audience or "gateway"

    @staticmethod
    def _normalize_path(path: str) -> str:
        normalized = (path or "").strip()
        if not normalized:
            return "/"
        if not normalized.startswith("/"):
            normalized = f"/{normalized}"
        if len(normalized) > 1 and normalized.endswith("/"):
            normalized = normalized.rstrip("/")
        return normalized

    def _build_auth_path(self, suffix: str) -> str:
        normalized_suffix = suffix.lstrip("/")
        if self._auth_path == "/":
            return f"/{normalized_suffix}"
        return f"{self._auth_path}/{normalized_suffix}"

    def request_bootstrap_challenge(
        self,
        device_id: str,
        key_id: str,
        audience: str = "gateway",
    ) -> BootstrapChallenge:
        payload = {
            "device_id": device_id,
            "key_id": key_id,
            "audience": audience or self._default_audience,
        }
        data = self._request_json(
            "POST",
            self._build_auth_path("bootstrap/challenge"),
            payload,
        )
        return self._parse_bootstrap_challenge(data)

    def submit_bootstrap_proof(
        self, request: BootstrapAuthenticateRequest
    ) -> EdgeAuthState:
        payload = self._build_bootstrap_auth_payload(request)
        data = self._request_json(
            "POST",
            self._build_auth_path("bootstrap/authenticate"),
            payload,
        )
        return self._parse_auth_state(data)

    def refresh_token_bundle(self, req: RefreshTokenRequest) -> EdgeTokenBundle | None:
        data = self._request_json(
            "POST",
            self._build_auth_path("token/refresh"),
            asdict(req),
        )
        return self._parse_token_bundle(data)

    def revoke_tokens(self, token_id: str | None, family_id: str | None) -> None:
        if not token_id and not family_id:
            return
        self._request_json(
            "POST",
            self._build_auth_path("token/revoke"),
            {
                "token_id": token_id,
                "family_id": family_id,
            },
        )

    def _request_json(
        self,
        method: str,
        path: str,
        payload: dict | None = None,
    ) -> dict:
        url = f"{self._base_url}{path}"
        headers = {"Content-Type": "application/json"}
        data = None
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")

        req = request.Request(url=url, data=data, headers=headers, method=method)
        try:
            with request.urlopen(req, timeout=self._timeout_sec) as resp:
                raw = resp.read()
        except HTTPError as err:
            details = ""
            try:
                details = err.read().decode("utf-8", errors="ignore")
            except Exception:
                details = ""
            raise RuntimeError(
                f"gateway auth request failed: method={method} path={path} "
                f"status={err.code} body={details}"
            ) from err
        except URLError as err:
            raise RuntimeError(
                f"gateway auth request failed: method={method} path={path} reason={err.reason}"
            ) from err

        if not raw:
            return {}
        parsed = json.loads(raw.decode("utf-8"))
        if not isinstance(parsed, dict):
            raise RuntimeError(
                f"gateway auth response is not an object: method={method} path={path}"
            )
        return parsed

    @staticmethod
    def _parse_bootstrap_challenge(payload: dict) -> BootstrapChallenge:
        issued_at_ms = payload.get("issued_at_ms", payload.get("issued_at", 0.0))
        expires_at_ms = payload.get("expires_at_ms", payload.get("expires_at", 0.0))
        issued_at = float(issued_at_ms) / 1000.0 if "issued_at_ms" in payload else float(issued_at_ms)
        expires_at = float(expires_at_ms) / 1000.0 if "expires_at_ms" in payload else float(expires_at_ms)

        return BootstrapChallenge(
            challenge_id=str(payload.get("challenge_id", "")),
            nonce=str(payload.get("nonce", "")),
            issuer=str(payload.get("issuer", "")),
            audience=str(payload.get("audience", "gateway")),
            issued_at=issued_at,
            expires_at=expires_at,
            entity_type=str(payload.get("entity_type", "device")),
            entity_id=str(payload.get("entity_id", "")),
            key_id=str(payload.get("key_id", "")),
        )

    @staticmethod
    def _build_bootstrap_auth_payload(
        request: BootstrapAuthenticateRequest,
    ) -> dict[str, object]:
        challenge = request.challenge
        signed = request.signed
        return {
            "challenge": {
                "challenge_id": challenge.challenge_id,
                "nonce": challenge.nonce,
                "issuer": challenge.issuer,
                "audience": challenge.audience,
                "issued_at_ms": int(round(challenge.issued_at * 1000.0)),
                "expires_at_ms": int(round(challenge.expires_at * 1000.0)),
                "entity_type": challenge.entity_type,
                "entity_id": challenge.entity_id,
                "key_id": challenge.key_id,
            },
            "signed": {
                "challenge_id": signed.challenge_id,
                "device_id": signed.device_id,
                "key_id": signed.key_id,
                "signature": signed.signature,
                "signature_algorithm": signed.signature_algorithm,
                "signed_at_ms": int(round(signed.signed_at * 1000.0)),
            },
            "scopes": list(request.scopes),
            "role": (request.role or "device").strip() or "device",
            "require_downstream_token": bool(request.require_downstream_token),
        }

    @staticmethod
    def _parse_edge_session(payload: dict | None) -> EdgeSession | None:
        if not isinstance(payload, dict):
            return None

        status_raw = str(payload.get("status", "active")).strip().lower()
        if status_raw not in {"active", "expired", "revoked"}:
            status_raw = "active"

        issued_at_ms = payload.get("issued_at_ms", payload.get("issued_at", 0.0))
        expires_at_ms = payload.get("expires_at_ms", payload.get("expires_at", 0.0))
        last_verified_at_ms = payload.get(
            "last_verified_at_ms", payload.get("last_verified_at", 0.0)
        )

        return EdgeSession(
            session_id=str(payload.get("session_id", "")),
            principal_id=str(payload.get("principal_id", "")),
            device_id=str(payload.get("device_id", "")),
            status=cast(SessionStatus, status_raw),
            issued_at=(float(issued_at_ms) / 1000.0 if "issued_at_ms" in payload else float(issued_at_ms)),
            expires_at=(float(expires_at_ms) / 1000.0 if "expires_at_ms" in payload else float(expires_at_ms)),
            token_family_id=str(payload.get("token_family_id", "")),
            last_verified_at=(
                float(last_verified_at_ms) / 1000.0
                if "last_verified_at_ms" in payload
                else float(last_verified_at_ms)
            ),
        )

    @staticmethod
    def _parse_edge_token(payload: dict | None, *, fallback_type: str) -> EdgeToken | None:
        if not isinstance(payload, dict):
            return None

        token_type_raw = str(payload.get("token_type", fallback_type)).strip().lower()
        if token_type_raw not in {"access", "refresh"}:
            token_type_raw = fallback_type if fallback_type in {"access", "refresh"} else "access"

        issued_at_ms = payload.get("issued_at_ms", payload.get("issued_at", 0.0))
        expires_at_ms = payload.get("expires_at_ms", payload.get("expires_at", 0.0))

        scopes = payload.get("scopes")
        if not isinstance(scopes, list):
            scopes = []
        return EdgeToken(
            raw=str(payload.get("raw", "")),
            token_type=cast(TokenType, token_type_raw),
            token_id=str(payload.get("token_id", "")),
            family_id=str(payload.get("family_id", "")),
            session_id=str(payload.get("session_id", "")),
            issued_at=(float(issued_at_ms) / 1000.0 if "issued_at_ms" in payload else float(issued_at_ms)),
            expires_at=(float(expires_at_ms) / 1000.0 if "expires_at_ms" in payload else float(expires_at_ms)),
            scopes=[str(item) for item in scopes],
            role=str(payload.get("role", "")),
        )

    @classmethod
    def _parse_token_bundle(cls, payload: dict) -> EdgeTokenBundle | None:
        access = cls._parse_edge_token(payload.get("access_token"), fallback_type="access")
        refresh = cls._parse_edge_token(
            payload.get("refresh_token"),
            fallback_type="refresh",
        )
        if access is None and refresh is None:
            return None
        return EdgeTokenBundle(access_token=access, refresh_token=refresh)

    @classmethod
    def _parse_auth_state(cls, payload: dict) -> EdgeAuthState:
        stage_raw = str(payload.get("stage", "ready")).strip().lower()
        if stage_raw not in {
            "uninitialized",
            "challenge_issued",
            "ready",
            "refreshing",
            "expired",
            "revoked",
            "failed",
        }:
            stage_raw = "ready"

        return EdgeAuthState(
            stage=cast(AuthStage, stage_raw),
            session=cls._parse_edge_session(payload.get("session")),
            tokens=cls._parse_token_bundle(payload.get("tokens") or {}),
            failure_reason=str(payload.get("failure_reason", "")),
        )
