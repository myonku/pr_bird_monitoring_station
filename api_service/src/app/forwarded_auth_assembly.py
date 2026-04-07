from __future__ import annotations

from src.adapters.grpc.server_adapter import GrpcServerAdapter
from src.services.auth.forwarded_auth_verifier_svc import (
    AuthorityBackedForwardedAuthVerifier,
)


def wire_forwarded_auth_revalidation(
    grpc_server: GrpcServerAdapter,
    verifier: AuthorityBackedForwardedAuthVerifier | None,
) -> AuthorityBackedForwardedAuthVerifier | None:
    """Wire inbound authority-backed forwarded-auth verification interceptor.

    This assembly function is intentionally lightweight and does not provide
    default implementations. It only defines integration wiring shape.
    """

    if verifier is None:
        return None

    grpc_server.add_forwarded_auth_interceptor(verifier)
    return verifier
