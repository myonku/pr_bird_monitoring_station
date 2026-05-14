from __future__ import annotations

import unittest

from src.models.auth.auth import SignatureAlgorithm
from src.models.auth.bootstrap import (
    BootstrapAuthenticateRequest,
    BootstrapChallenge,
    SignedBootstrapProof,
)
from src.transport.auth_transport import EdgeGatewayAuthHttpClient


class _CapturingEdgeGatewayAuthHttpClient(EdgeGatewayAuthHttpClient):
    def __init__(self) -> None:
        super().__init__(auth_base_url="http://gateway.example")
        self.captured_method: str | None = None
        self.captured_path: str | None = None
        self.captured_payload: dict | None = None

    def _request_json(self, method: str, path: str, payload: dict | None = None) -> dict:
        self.captured_method = method
        self.captured_path = path
        self.captured_payload = payload
        return {"stage": "ready"}


class EdgeGatewayAuthHttpClientBootstrapTests(unittest.TestCase):
    def test_submit_bootstrap_proof_sends_complete_auth_request(self) -> None:
        client = _CapturingEdgeGatewayAuthHttpClient()
        challenge = BootstrapChallenge(
            challenge_id="11111111-1111-1111-1111-111111111111",
            nonce="nonce-1",
            issuer="gateway",
            audience="gateway",
            issued_at=1747210000.25,
            expires_at=1747210060.25,
            entity_type="device",
            entity_id="device-1",
            key_id="key-1",
        )
        proof = SignedBootstrapProof(
            challenge_id=challenge.challenge_id,
            device_id="device-1",
            key_id="key-1",
            signature="signature-1",
            signature_algorithm="ed25519",
            signed_at=1747210005.5,
        )

        state = client.submit_bootstrap_proof(
            BootstrapAuthenticateRequest(
                challenge=challenge,
                signed=proof,
                scopes=["service:bootstrap"],
                role="device",
                require_downstream_token=False,
            )
        )

        self.assertEqual("POST", client.captured_method)
        self.assertEqual("/v1/edge/auth/bootstrap/authenticate", client.captured_path)
        self.assertIsInstance(client.captured_payload, dict)
        payload = client.captured_payload or {}
        self.assertEqual(challenge.challenge_id, payload["challenge"]["challenge_id"])
        self.assertEqual(1747210000250, payload["challenge"]["issued_at_ms"])
        self.assertEqual(1747210060250, payload["challenge"]["expires_at_ms"])
        self.assertEqual(challenge.challenge_id, payload["signed"]["challenge_id"])
        self.assertEqual(1747210005500, payload["signed"]["signed_at_ms"])
        self.assertEqual(["service:bootstrap"], payload["scopes"])
        self.assertFalse(payload["require_downstream_token"])
        self.assertEqual("device", payload["role"])
        self.assertEqual("ready", state.stage)

    def test_parse_bootstrap_challenge_supports_ms_fields(self) -> None:
        challenge = EdgeGatewayAuthHttpClient._parse_bootstrap_challenge(
            {
                "challenge_id": "11111111-1111-1111-1111-111111111111",
                "nonce": "nonce-1",
                "issuer": "gateway",
                "audience": "gateway",
                "issued_at_ms": 1747210000250,
                "expires_at_ms": 1747210060250,
                "entity_type": "device",
                "entity_id": "device-1",
                "key_id": "key-1",
            }
        )

        self.assertEqual("11111111-1111-1111-1111-111111111111", challenge.challenge_id)
        self.assertAlmostEqual(1747210000.25, challenge.issued_at)
        self.assertAlmostEqual(1747210060.25, challenge.expires_at)
        self.assertEqual("key-1", challenge.key_id)

    def test_parse_auth_state_supports_ms_fields(self) -> None:
        state = EdgeGatewayAuthHttpClient._parse_auth_state(
            {
                "stage": "ready",
                "session": {
                    "session_id": "session-1",
                    "principal_id": "service:edge-1",
                    "device_id": "edge-1",
                    "status": "active",
                    "issued_at_ms": 1747210000250,
                    "expires_at_ms": 1747213600250,
                    "token_family_id": "family-1",
                    "last_verified_at_ms": 1747210001250,
                },
                "tokens": {
                    "access_token": {
                        "raw": "access-token",
                        "token_type": "access",
                        "token_id": "access-1",
                        "family_id": "family-1",
                        "session_id": "session-1",
                        "issued_at_ms": 1747210000250,
                        "expires_at_ms": 1747210300250,
                        "scopes": ["edge:upload"],
                        "role": "device",
                    },
                    "refresh_token": {
                        "raw": "refresh-token",
                        "token_type": "refresh",
                        "token_id": "refresh-1",
                        "family_id": "family-1",
                        "session_id": "session-1",
                        "issued_at_ms": 1747210000250,
                        "expires_at_ms": 1747296400250,
                        "scopes": ["edge:upload"],
                        "role": "device",
                    },
                },
                "failure_reason": "",
            }
        )

        self.assertEqual("ready", state.stage)
        self.assertIsNotNone(state.session)
        self.assertIsNotNone(state.tokens)
        session = state.session
        tokens = state.tokens
        self.assertIsNotNone(tokens.access_token)
        self.assertIsNotNone(tokens.refresh_token)
        access_token = tokens.access_token
        refresh_token = tokens.refresh_token
        self.assertAlmostEqual(1747213600.25, session.expires_at)
        self.assertAlmostEqual(1747296400.25, refresh_token.expires_at)
        self.assertAlmostEqual(1747210300.25, access_token.expires_at)
