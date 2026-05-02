from __future__ import annotations

import json as std_json
import time
import unittest
from types import SimpleNamespace
from typing import Any, cast
from uuid import NAMESPACE_DNS, UUID, uuid4, uuid5

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from src.iface.common.local_credential_manager import ModuleCredentialSnapshot
from src.models.auth.auth import (
    IdentityContext,
    IssuedToken,
    Principal,
    Session,
    TokenBundle,
    TokenClaims,
)
from src.models.auth.bootstrap import ChallengePayload
from src.models.sys.config import AuthConfig, ProjectConfig, RuntimeConfig, SecretKeyStartupParams
from src.models.common.instance import ServiceInstance
from src.services.common.local_credential_svc import (
    LocalCredentialService,
    is_credential_valid_for_discovery,
)
from src.services.communication.rpc_client.auth_authority_bootstrap_rpc_client import (
    _normalize_challenge_request,
)
from src.services.auth.bootstrap_coordinator_svc import (
    BootstrapCoordinatorService,
    _build_bootstrap_challenge_request,
)
from src.services.orchestration.startup_security_svc import (
    resolve_startup_security_materials,
)
from src.services.orchestration.credential_discovery_supervisor_svc import (
    CredentialDiscoverySupervisorService,
)
from src.utils.crypto_utils import CryptoUtils


class FakeRedis:
    def __init__(self) -> None:
        self._store: dict[str, bytes | str] = {}

    async def set(self, key: str, value: bytes | str, ex: int | None = None) -> None:
        self._store[key] = value

    async def get(self, key: str):
        return self._store.get(key)

    async def delete(self, key: str) -> None:
        self._store.pop(key, None)


class FakeTrafficStation:
    def __init__(self) -> None:
        self.outbound_calls: list[str] = []

    async def handle_inbound(self, req):
        raise NotImplementedError

    async def send_outbound(self, req):
        self.outbound_calls.append(getattr(req.flow, "route_key", ""))
        return SimpleNamespace(target_endpoint="127.0.0.1:50051", profile=None, payload="")


class FakeRegistryService:
    def __init__(self) -> None:
        self.register_calls: list[tuple[str, str]] = []
        self.unregister_calls: list[tuple[str, str]] = []

    async def register(self, instance, ttl_sec: int) -> None:
        self.register_calls.append((instance.name, instance.active_comm_key_id))

    async def unregister(self, instance) -> None:
        self.unregister_calls.append((instance.name, instance.active_comm_key_id))

    async def get_service_instances(self, service_name: str):
        return []

    async def get_service_snapshot(self, service_name: str):
        return None

    async def choose_endpoint(self, service_name: str, affinity_key: str = "", require_tags: list[str] | None = None):
        return None


class FakeSecretKeyService:
    def __init__(self, private_key_pem: str) -> None:
        self._private_key_pem = private_key_pem

    async def get_private_key_ref(self):
        return SimpleNamespace(private_key_ref=self._private_key_pem)


def build_worker_instance(runtime_cfg: RuntimeConfig, active_key_id: str) -> ServiceInstance:
    instance_id = _parse_or_create_uuid(runtime_cfg.instance_id)
    service_id = runtime_cfg.instance_id.strip() or str(instance_id)
    resolved_active_key_id = active_key_id.strip() or service_id
    return ServiceInstance(
        id=instance_id,
        service_id=service_id,
        name=runtime_cfg.service_name,
        endpoint=f"{runtime_cfg.grpc_listen_host}:{runtime_cfg.grpc_listen_port}",
        heartbeat=0,
        weight=1,
        tags=["data_worker", "grpc", "startup_phase"],
        active_comm_key_id=resolved_active_key_id,
        metadata={
            "run_mode": runtime_cfg.run_mode,
            "startup_phase": "bootstrap_to_registry",
        },
    )


def _parse_or_create_uuid(raw: str) -> UUID:
    candidate = (raw or "").strip()
    if candidate:
        try:
            return UUID(candidate)
        except ValueError:
            return uuid5(NAMESPACE_DNS, candidate)
    return uuid4()


class CredentialFlowTests(unittest.IsolatedAsyncioTestCase):
    def test_bootstrap_signature_payload_and_signing(self) -> None:
        private_key = ed25519.Ed25519PrivateKey.generate()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        challenge = ChallengePayload(
            challenge_id=uuid4(),
            issuer="certification_server",
            audience="data_worker",
            entity_type="service",
            entity_id="data_worker",
            key_id="dw-key",
            nonce="nonce-1",
            issued_at=1700000000.5,
            expires_at=1700000060.5,
        )
        payload = CryptoUtils.build_bootstrap_signature_payload(
            challenge,
            key_id="dw-key",
            entity_type="service",
            entity_id="data_worker",
        )
        algorithm = CryptoUtils.detect_signature_algorithm_from_private_key(private_pem)
        signature = CryptoUtils.sign_by_algorithm(algorithm, payload, private_pem)
        CryptoUtils.verify_by_algorithm(algorithm, payload, signature, public_pem)

    async def test_local_credential_round_trip_and_legacy_payload(self) -> None:
        redis_client = FakeRedis()
        service = LocalCredentialService(cast(Any, redis_client))
        now = time.time()

        principal = Principal(entity_type="service", entity_id="data_worker")
        identity = IdentityContext(
            principal=principal,
            entity_type="service",
            entity_id="data_worker",
            principal_id=principal.principal_id(),
            session_id=uuid4(),
            token_id=uuid4(),
            token_family_id=uuid4(),
            token_type="access",
            role="service",
            scopes=["service:bootstrap"],
            auth_method="service_secret",
            source_ip="127.0.0.1",
            client_id="data_worker",
            gateway_id="",
            source_service="certification_server",
            target_service="data_worker",
            user_agent="data_worker-test",
            request_id="req-1",
            trace_id="trace-1",
            issued_at=now,
            expires_at=now + 3600,
        )
        session = Session(
            id=uuid4(),
            principal=principal,
            entity_type="service",
            entity_id="data_worker",
            principal_id=principal.principal_id(),
            status="active",
            auth_method="service_secret",
            created_by_ip="127.0.0.1",
            last_seen_ip="127.0.0.1",
            user_agent="data_worker-test",
            client_id="data_worker",
            gateway_id="",
            scope_snapshot=["service:bootstrap"],
            role_snapshot="service",
            token_family_id=uuid4(),
            created_at=now,
            updated_at=now,
            last_seen_at=now,
            last_verified_at=now,
            next_refresh_at=now + 300,
            expires_at=now + 3600,
            revoked_at=0.0,
            version=1,
        )
        snapshot = ModuleCredentialSnapshot(
            principal_id=principal.principal_id(),
            stage="ready",
            identity=identity,
            session=session,
            tokens=TokenBundle(
                access_token=IssuedToken(raw="access-token", type="access", ttl_sec=300),
                refresh_token=IssuedToken(raw="refresh-token", type="refresh", ttl_sec=600),
            ),
            active_comm_key_id="dw-key",
            issued_at=now,
            expires_at=now + 3600,
            updated_at=now,
            metadata={"credential_status": "active"},
        )

        key = await service.save_bootstrap_credential(snapshot)
        self.assertIn("/bms/local_credentials/", key)
        loaded = await service.load_active_credential(principal.principal_id())
        assert loaded is not None
        assert loaded.identity is not None
        assert loaded.session is not None
        assert loaded.tokens is not None
        assert loaded.tokens.refresh_token is not None
        self.assertTrue(is_credential_valid_for_discovery(loaded, now=now + 10))

        legacy_payload = {
            "principal_id": "service:legacy",
            "stage": "ready",
            "active_comm_key_id": "legacy-key",
            "issued_at": now,
            "expires_at": now + 100,
            "updated_at": now,
            "metadata": {"credential_status": "active"},
        }
        await redis_client.set(
            "/bms/local_credentials/service:legacy",
            std_json.dumps(legacy_payload, ensure_ascii=True),
        )
        legacy_loaded = await service.load_active_credential("service:legacy")
        assert legacy_loaded is not None
        self.assertIsNone(legacy_loaded.identity)
        self.assertEqual(legacy_loaded.active_comm_key_id, "legacy-key")

    def test_no_auth_startup_materials_do_not_touch_secret_dir(self) -> None:
        runtime_cfg = RuntimeConfig(
            entity_type="service",
            service_name="data_worker",
            instance_id="worker-1",
            run_mode="no_auth",
            grpc_listen_host="127.0.0.1",
            grpc_listen_port=50052,
        )
        config = ProjectConfig(
            auth=AuthConfig(secret_key_dir="does/not/exist", active_key_id=""),
            runtime=runtime_cfg,
        )

        startup_params, secret_key_service = resolve_startup_security_materials(
            config=config,
            runtime_cfg=runtime_cfg.normalized("data_worker"),
            default_entity_id="data_worker",
        )

        self.assertIsNone(secret_key_service)
        self.assertEqual(startup_params.instance_id, "worker-1")
        self.assertEqual(startup_params.entity_id, "worker-1")
        self.assertEqual(startup_params.entity_type, "service")

    def test_bootstrap_challenge_request_uses_proto_supported_entity_type(self) -> None:
        runtime_cfg = RuntimeConfig(
            entity_type="instance",
            service_name="data_worker",
            instance_id="worker-1",
            run_mode="development",
            grpc_listen_host="127.0.0.1",
            grpc_listen_port=50052,
        )
        startup_params = SecretKeyStartupParams(
            secret_key_dir="secret_keys",
            active_key_id="dw-key",
            entity_type="instance",
            entity_id="worker-1",
            entity_name="data_worker",
            instance_id="worker-1",
            instance_name="data_worker",
        )

        challenge_request = _build_bootstrap_challenge_request(
            runtime_cfg=runtime_cfg,
            startup_params=startup_params,
        )

        self.assertEqual(challenge_request.entity_type, "service")

    async def test_supervisor_bootstrap_refresh_and_registry(self) -> None:
        runtime_cfg = RuntimeConfig(
            entity_type="service",
            service_name="data_worker",
            instance_id="worker-1",
            run_mode="development",
            grpc_listen_host="127.0.0.1",
            grpc_listen_port=50052,
        )
        startup_params = SecretKeyStartupParams(
            secret_key_dir="secret_keys",
            active_key_id="dw-key",
            entity_type="service",
            entity_id="worker-1",
            entity_name="data_worker",
            instance_id="worker-1",
            instance_name="data_worker",
        )
        principal = Principal(entity_type="service", entity_id="worker-1")
        now = time.time()
        bootstrap_result = self._build_bootstrap_result(principal, now=now)
        refreshed_bundle = TokenBundle(
            access_token=IssuedToken(raw="access-refreshed", type="access", ttl_sec=120),
            refresh_token=IssuedToken(raw="refresh-refreshed", type="refresh", ttl_sec=240),
        )

        redis_client = FakeRedis()
        local_credential_manager = LocalCredentialService(cast(Any, redis_client))
        traffic_station = FakeTrafficStation()
        registry_service = FakeRegistryService()
        secret_key_service = FakeSecretKeyService(private_key_pem="-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----\n")
        bootstrap_coordinator = BootstrapCoordinatorService(
            runtime_cfg=runtime_cfg,
            startup_params=startup_params,
            traffic_station=cast(Any, traffic_station),
            local_credential_manager=cast(Any, local_credential_manager),
            secret_key_service=cast(Any, secret_key_service),
        )
        supervisor = CredentialDiscoverySupervisorService(
            runtime_cfg=runtime_cfg,
            local_credential_manager=cast(Any, local_credential_manager),
            registry_service=cast(Any, registry_service),
            service_instance_factory=lambda active_key_id: build_worker_instance(runtime_cfg, active_key_id),
            bootstrap_coordinator=cast(Any, bootstrap_coordinator),
        )

        from unittest.mock import AsyncMock, patch

        with patch(
            "src.services.communication.rpc_client.auth_authority_bootstrap_rpc_client.AuthAuthorityBootstrapRPCClient.execute_bootstrap_handshake",
            AsyncMock(return_value=bootstrap_result),
        ), patch(
            "src.services.communication.rpc_client.auth_authority_token_refresh_rpc_client.AuthAuthorityTokenRefreshRPCClient.execute_refresh_token_bundle",
            AsyncMock(return_value=refreshed_bundle),
        ):
            registered_instance = await supervisor.reconcile_once(registered_instance=None)
            self.assertIsNotNone(registered_instance)
            self.assertEqual(registry_service.register_calls, [("data_worker", "dw-key")])

            snapshot = await local_credential_manager.load_active_credential("service:worker-1")
            assert snapshot is not None
            assert snapshot.tokens is not None
            assert snapshot.tokens.refresh_token is not None
            assert snapshot.session is not None
            self.assertEqual(snapshot.tokens.refresh_token.raw, "refresh-bootstrap")

            refreshed_instance = await supervisor.reconcile_once(
                registered_instance=registered_instance,
            )
            self.assertIsNotNone(refreshed_instance)
            self.assertEqual(registry_service.register_calls, [("data_worker", "dw-key")])
            refreshed_snapshot = await local_credential_manager.load_active_credential("service:worker-1")
            assert refreshed_snapshot is not None
            assert refreshed_snapshot.tokens is not None
            assert refreshed_snapshot.tokens.refresh_token is not None
            assert refreshed_snapshot.session is not None
            self.assertEqual(refreshed_snapshot.tokens.refresh_token.raw, "refresh-refreshed")
            self.assertGreater(refreshed_snapshot.session.next_refresh_at, snapshot.session.next_refresh_at)
            self.assertGreaterEqual(refreshed_snapshot.session.version, snapshot.session.version + 1)

    def _build_bootstrap_result(self, principal: Principal, *, now: float):
        identity = IdentityContext(
            principal=principal,
            entity_type=principal.entity_type,
            entity_id=principal.entity_id,
            principal_id=principal.principal_id(),
            session_id=uuid4(),
            token_id=uuid4(),
            token_family_id=uuid4(),
            token_type="access",
            role="service",
            scopes=["service:bootstrap"],
            auth_method="service_secret",
            source_ip="127.0.0.1",
            client_id="data_worker",
            gateway_id="",
            source_service="certification_server",
            target_service="data_worker",
            user_agent="data_worker-test",
            request_id="req-bootstrap",
            trace_id="trace-bootstrap",
            issued_at=now,
            expires_at=now + 3600,
        )
        session = Session(
            id=uuid4(),
            principal=principal,
            entity_type=principal.entity_type,
            entity_id=principal.entity_id,
            principal_id=principal.principal_id(),
            status="active",
            auth_method="service_secret",
            created_by_ip="127.0.0.1",
            last_seen_ip="127.0.0.1",
            user_agent="data_worker-test",
            client_id="data_worker",
            gateway_id="",
            scope_snapshot=["service:bootstrap"],
            role_snapshot="service",
            token_family_id=uuid4(),
            created_at=now,
            updated_at=now,
            last_seen_at=now,
            last_verified_at=now,
            next_refresh_at=now - 10,
            expires_at=now + 3600,
            revoked_at=0.0,
            version=1,
        )
        tokens = TokenBundle(
            access_token=IssuedToken(raw="access-bootstrap", type="access", ttl_sec=300),
            refresh_token=IssuedToken(raw="refresh-bootstrap", type="refresh", ttl_sec=600),
        )
        return SimpleNamespace(
            stage="ready",
            identity=identity,
            session=session,
            tokens=tokens,
            active_comm_key_id="dw-key",
            issued_at=now,
            expires_at=now + 3600,
        )
