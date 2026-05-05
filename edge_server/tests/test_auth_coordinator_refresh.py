import sys
import time
from pathlib import Path
from typing import cast
from unittest import TestCase, main


EDGE_SERVER_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(EDGE_SERVER_ROOT))

from src.iface.auth_interface import IEdgeAuthStateStore, IEdgeGatewayAuthClient, ISecretKeyManager
from src.models.auth.auth import EdgeSession, EdgeToken, EdgeTokenBundle, LocalTrustMaterial
from src.models.auth.auth_contract import EdgeAuthState, RefreshTokenRequest
from src.orchestration.auth_coordinator import EdgeAuthCoordinator


class _FakeKeyManager(ISecretKeyManager):
    def get_local_trust_material(self) -> LocalTrustMaterial:
        raise AssertionError("unexpected bootstrap path")

    def get_public_key_pem(self) -> bytes:
        raise AssertionError("unexpected bootstrap path")

    def get_private_key_pem(self) -> bytes:
        raise AssertionError("unexpected bootstrap path")


class _MemoryAuthStateStore(IEdgeAuthStateStore):
    def __init__(self, initial_state: EdgeAuthState | None) -> None:
        self.state = initial_state
        self.saved_states: list[EdgeAuthState] = []
        self.cleared_reasons: list[str] = []

    def load(self) -> EdgeAuthState | None:
        return self.state

    def save(self, state: EdgeAuthState) -> None:
        self.state = state
        self.saved_states.append(state)

    def clear(self, reason: str = "") -> None:
        self.state = None
        self.cleared_reasons.append(reason)


class _FakeGatewayAuthClient(IEdgeGatewayAuthClient):
    def __init__(self, refreshed_bundle: EdgeTokenBundle) -> None:
        self.refreshed_bundle = refreshed_bundle
        self.refresh_requests: list[RefreshTokenRequest] = []

    def request_bootstrap_challenge(self, device_id: str, key_id: str, audience: str = "gateway"):
        raise AssertionError("unexpected bootstrap path")

    def submit_bootstrap_proof(self, proof):
        raise AssertionError("unexpected bootstrap path")

    def refresh_token_bundle(self, req: RefreshTokenRequest) -> EdgeTokenBundle | None:
        self.refresh_requests.append(req)
        return self.refreshed_bundle

    def revoke_tokens(self, token_id: str | None, family_id: str | None) -> None:
        raise AssertionError("unexpected revoke path")


class EdgeAuthCoordinatorRefreshTests(TestCase):
    def test_refresh_preserves_missing_refresh_expiry_metadata(self) -> None:
        now_ts = time.time()
        previous_state = EdgeAuthState(
            stage="ready",
            session=EdgeSession(
                session_id="session-1",
                principal_id="principal-1",
                device_id="device-1",
                status="active",
                issued_at=now_ts - 600,
                expires_at=now_ts + 3600,
                token_family_id="family-1",
                last_verified_at=now_ts - 300,
            ),
            tokens=EdgeTokenBundle(
                access_token=EdgeToken(
                    raw="old-access",
                    token_type="access",
                    token_id="access-1",
                    family_id="family-1",
                    session_id="session-1",
                    issued_at=now_ts - 600,
                    expires_at=now_ts - 1,
                    scopes=["edge:upload"],
                    role="device",
                ),
                refresh_token=EdgeToken(
                    raw="old-refresh",
                    token_type="refresh",
                    token_id="refresh-1",
                    family_id="family-1",
                    session_id="session-1",
                    issued_at=now_ts - 600,
                    expires_at=now_ts + 86400,
                    scopes=["edge:upload"],
                    role="device",
                ),
            ),
        )

        refreshed_bundle = EdgeTokenBundle(
            access_token=EdgeToken(
                raw="new-access",
                token_type="access",
                token_id="access-2",
                family_id="family-1",
                session_id="session-1",
                issued_at=now_ts,
                expires_at=now_ts + 300,
                scopes=["edge:upload"],
                role="device",
            ),
            refresh_token=EdgeToken(
                raw="new-refresh",
                token_type="refresh",
                token_id="refresh-2",
                family_id="family-1",
                session_id="session-1",
                issued_at=now_ts,
                expires_at=0.0,
                scopes=["edge:upload"],
                role="device",
            ),
        )

        store = _MemoryAuthStateStore(previous_state)
        client = _FakeGatewayAuthClient(refreshed_bundle)
        coordinator = EdgeAuthCoordinator(
            key_manager=_FakeKeyManager(),
            gateway_auth_client=client,
            state_store=store,
            access_token_skew_sec=30,
        )

        state = coordinator.ensure_ready(now_ts=now_ts)

        self.assertIsNotNone(state.tokens)
        tokens = cast(EdgeTokenBundle, state.tokens)
        previous_tokens = cast(EdgeTokenBundle, previous_state.tokens)
        access_token = cast(EdgeToken, tokens.access_token)
        refresh_token = cast(EdgeToken, tokens.refresh_token)
        previous_refresh_token = cast(EdgeToken, previous_tokens.refresh_token)

        self.assertEqual(access_token.raw, "new-access")
        self.assertEqual(refresh_token.raw, "new-refresh")
        self.assertEqual(
            refresh_token.expires_at,
            previous_refresh_token.expires_at,
        )
        self.assertGreater(refresh_token.expires_at, now_ts)
        self.assertGreaterEqual(len(store.saved_states), 1)
        self.assertEqual(len(client.refresh_requests), 1)


if __name__ == "__main__":
    main()