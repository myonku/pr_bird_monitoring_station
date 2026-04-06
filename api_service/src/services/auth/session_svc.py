from uuid import UUID

from src.models.auth.auth import Session, SessionTouchMeta
from src.models.auth.auth_contract import SessionValidateRequest


class SessionService:
    """会话服务。运行期不回源认证中心。"""

    def __init__(self) -> None:
        pass

    def upsert_session(self, session: Session | None) -> None:
        # 非认证中心模块不再维护本地会话状态。
        _ = session

    async def upsert_session_async(self, session: Session | None) -> None:
        _ = session

    async def get_session(self, session_id: str) -> Session | None:
        try:
            UUID(session_id)
        except ValueError:
            return None
        return None

    async def touch_session(self, session_id: str, meta: SessionTouchMeta) -> None:
        # 触达元信息由认证中心统一管理；本模块不做本地触达更新。
        _ = (session_id, meta)

    async def validate_session(self, req: SessionValidateRequest) -> Session | None:
        _ = req
        return None
