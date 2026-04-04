from uuid import UUID

from src.models.auth.auth import Session, SessionTouchMeta
from src.models.auth.auth_contract import SessionValidateRequest
from src.services.auth.auth_gateway_authority import IAuthGatewayAuthorityClient


class SessionService:
    """会话服务（只通过认证中心查询/校验，不维护本地会话状态）。"""

    def __init__(self, authority_client: IAuthGatewayAuthorityClient):
        self._authority_client = authority_client

    def upsert_session(self, session: Session | None) -> None:
        # 非认证中心模块不再维护本地会话状态。
        _ = session

    async def upsert_session_async(self, session: Session | None) -> None:
        _ = session

    async def get_session(self, session_id: str) -> Session | None:
        try:
            sid = UUID(session_id)
        except ValueError:
            return None
        return await self._authority_client.validate_session(
            SessionValidateRequest(
                session_id=sid,
                principal_id="",
                require_active=False,
                min_version=0,
            )
        )

    async def touch_session(self, session_id: str, meta: SessionTouchMeta) -> None:
        # 触达元信息由认证中心统一管理；本模块不做本地触达更新。
        _ = (session_id, meta)

    async def validate_session(self, req: SessionValidateRequest) -> Session | None:
        return await self._authority_client.validate_session(req)
