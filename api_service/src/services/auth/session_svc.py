from src.models.auth.auth import Session, SessionTouchMeta
from src.models.auth.auth_contract import SessionValidateRequest


class SessionService:
    """会话读取、更新和状态校验服务。"""

    def __init__(self): ...

    async def get_session(self, session_id: str) -> Session | None: ...

    async def touch_session(self, session_id: str, meta: SessionTouchMeta) -> None: ...

    async def validate_session(self, req: SessionValidateRequest) -> Session | None: ...
