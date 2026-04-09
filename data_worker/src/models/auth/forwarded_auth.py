from msgspec import Struct

from src.models.auth.auth import IdentityContext, Session


class ForwardedAuthContext(Struct, kw_only=True):
    """网关向其他业务服务转发的认证上下文，包括主体标识、会话和令牌信息，以及服务间调用的相关元数据等。"""

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
    """网关认证上下文验证结果，包括是否允许访问、身份上下文和会话信息，以及验证失败的原因等。"""

    allowed: bool
    identity: IdentityContext | None = None
    session: Session | None = None
    failure_reason: str = ""
