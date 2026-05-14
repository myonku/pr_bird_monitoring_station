from __future__ import annotations

import unittest

from src.gen.auth.v1 import auth_authority_bootstrap_pb2 as bootstrap_pb2
from src.services.communication.rpc_client.auth_authority_token_refresh_rpc_client import (
    _from_proto_token_type,
    _to_local_issued_token,
)


class AuthAuthorityTokenRefreshRPCClientTests(unittest.TestCase):
    def test_unspecified_token_type_is_treated_as_missing(self) -> None:
        token = bootstrap_pb2.IssuedToken(
            raw="refresh-token",
            token_type=bootstrap_pb2.TOKEN_TYPE_UNSPECIFIED,
            ttl_sec=120,
        )

        self.assertIsNone(_from_proto_token_type(token.token_type))
        self.assertIsNone(_to_local_issued_token(token))

    def test_known_token_type_is_mapped(self) -> None:
        token = bootstrap_pb2.IssuedToken(
            raw="refresh-token",
            token_type=bootstrap_pb2.TOKEN_TYPE_REFRESH,
            ttl_sec=120,
        )

        mapped = _to_local_issued_token(token)

        self.assertIsNotNone(mapped)
        self.assertEqual("refresh-token", mapped.raw)
        self.assertEqual("refresh", mapped.type)
        self.assertEqual(120, mapped.ttl_sec)
