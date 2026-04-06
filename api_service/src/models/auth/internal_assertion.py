from msgspec import Struct, field


class InternalAssertionHeader(Struct, kw_only=True):
    """内部断言头（类 JWS Header）。"""

    ver: str
    alg: str
    kid: str
    typ: str = ""


class InternalAssertionClaims(Struct, kw_only=True):
    """内部断言负载。"""

    ver: str = ""

    iss: str
    aud: str
    jti: str
    iat: int
    exp: int

    principal_id: str = ""
    entity_type: str = ""
    entity_id: str = ""

    session_id: str = ""
    token_id: str = ""

    scopes: list[str] = field(default_factory=list)
    gateway_id: str = ""

    trace_id: str = ""
    request_id: str = ""

    method: str = ""
    path: str = ""

    query_hash: str = ""
    body_sha256: str = ""
    secure_channel_id: str = ""


class VerifiedInternalIdentity(Struct, kw_only=True):
    """断言验签成功后产出的已验证身份上下文。"""

    principal_id: str
    entity_type: str
    entity_id: str

    session_id: str
    token_id: str

    gateway_id: str
    source_service: str
    target_service: str

    trace_id: str
    request_id: str

    scopes: list[str] = field(default_factory=list)
    jti: str = ""
    key_id: str = ""


class InternalAssertionVerifyRequest(Struct, kw_only=True):
    """内部断言验证输入。"""

    method: str
    path: str = ""

    query: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)
