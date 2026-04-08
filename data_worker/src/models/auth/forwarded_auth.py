from msgspec import Struct

from src.models.auth.auth import IdentityContext, Session


class ForwardedAuthContext(Struct, kw_only=True):
    """Gateway -> service forwarded auth context carried in headers."""

    principal_id: str
    session_id: str
    token_id: str

    source_service: str = ""
    target_service: str = ""
    binding_type: str = ""

    gateway_id: str = ""
    verify_mode: str = ""

    grant_issued_at: int = 0
    grant_expires_at: int = 0

    trace_id: str = ""
    request_id: str = ""


class ForwardedAuthVerificationResult(Struct, kw_only=True):
    """Inbound forwarded auth verification result contract."""

    allowed: bool
    identity: IdentityContext | None = None
    session: Session | None = None
    failure_reason: str = ""
