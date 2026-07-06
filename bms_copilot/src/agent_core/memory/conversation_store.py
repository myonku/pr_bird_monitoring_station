import json
import time
from typing import Any

from redis.asyncio import Redis

from src.iface.agent.memory import ISessionMemory
from src.models.agent.api import ChatMessage
from src.iface.agent_resource.session_store import ISessionStore
from src.iface.agent_resource.turn_store import ITurnStore
from src.iface.agent_resource.working_state_cache import IWorkingStateCache
from src.models.agent.context import SessionWorkingState
from src.models.agent.schemas import (
    AgentRequest,
    AgentResponse,
    IntentResult,
    ToolCall,
    ToolResult,
)
from src.models.agent.session import AgentSession

_KEY_PREFIX = "bms_copilot:session"
_MAX_MESSAGES = 200  # 单会话最多保留的消息数，超出后裁剪旧消息


def _mk(session_id: str) -> str:
    return f"{_KEY_PREFIX}:{session_id}:messages"


def _now_ms() -> int:
    return int(time.time() * 1000)


class ConversationMemory(ISessionMemory):
    """基于 Redis 的会话记忆实现。

    职责：
    - 用户消息 ↔ 助手消息的持久化（messages list）
    - 会话生命周期管理（session_store）
    - 轮次记录归档（turn_store）
    - 当前轮次中间状态跟踪（working_state_cache）
    """

    def __init__(
        self,
        redis: Redis,
        session_store: ISessionStore,
        turn_store: ITurnStore,
        working_state_cache: IWorkingStateCache | None = None,
    ) -> None:
        if redis is None:
            raise ValueError("redis client is required")
        if session_store is None:
            raise ValueError("session_store is required")
        if turn_store is None:
            raise ValueError("turn_store is required")

        self._redis = redis
        self._session_store = session_store
        self._turn_store = turn_store
        self._state_cache = working_state_cache


    async def get_recent_messages(
        self, session_id: str, limit: int = 20
    ) -> list[ChatMessage]:
        """读取最近的会话消息，按时间正序返回。"""
        raw_list = await self._redis.lrange(_mk(session_id), -limit, -1)
        return [_decode_message(item) for item in raw_list if item]


    async def append_user_request(self, req: AgentRequest) -> None:
        """存储用户请求，并确保会话已创建。"""

        existing = await self._session_store.get_session(req.session_id)
        if existing is not None:
            return
        session = AgentSession(
            session_id=req.session_id,
            user_id=req.user_id,
        )
        await self._session_store.create_session(session)

        msg: dict[str, Any] = {
            "role": "user",
            "content": req.text,
            "timestamp_ms": _now_ms(),
            "request_id": req.request_id,
        }
        await self._redis.rpush(
            _mk(req.session_id), json.dumps(msg, ensure_ascii=False)
        )
        await self._trim_messages(req.session_id)

        # 初始化当前轮次的工作状态
        if self._state_cache is not None:
            state = SessionWorkingState(
                session_id=req.session_id,
                user_id=req.user_id,
                last_request_id=req.request_id,
            )
            await self._state_cache.set_state(state)

    async def append_assistant_response(self, res: AgentResponse) -> None:
        """存储助手响应，并归档完整轮次记录。"""
        msg: dict[str, Any] = {
            "role": "assistant",
            "content": res.answer.text or "",
            "timestamp_ms": _now_ms(),
            "request_id": res.request_id,
        }
        await self._redis.rpush(
            _mk(res.session_id), json.dumps(msg, ensure_ascii=False)
        )
        await self._trim_messages(res.session_id)

        # 归档轮次记录
        turn: dict[str, Any] = {
            "request_id": res.request_id,
            "session_id": res.session_id,
            "intent_type": res.debug.intent,
            "tool_names": list(res.debug.tools),
            "status": (
                res.status.value if hasattr(res.status, "value") else str(res.status)
            ),
            "answer_text": (res.answer.text or "")[:500],
            "timestamp_ms": _now_ms(),
        }
        await self._turn_store.append_turn(res.session_id, turn)

        # 更新会话摘要字段
        await self._session_store.touch_session(res.session_id)

        # 清理工作状态
        if self._state_cache is not None:
            await self._state_cache.clear_state(res.session_id)

    async def append_intent(self, session_id: str, intent: IntentResult) -> None:
        """在轮次工作状态中记录意图识别结果。"""
        if self._state_cache is None:
            return
        state = await self._state_cache.get_state(session_id)
        if state is None:
            return
        state.last_intent_type = (
            intent.intent_type.value
            if hasattr(intent.intent_type, "value")
            else str(intent.intent_type)
        )
        await self._state_cache.set_state(state)

    async def append_tool_call(self, session_id: str, call: ToolCall) -> None:
        """在轮次工作状态中记录工具调用。"""
        if self._state_cache is None:
            return
        state = await self._state_cache.get_state(session_id)
        if state is None:
            return
        state.last_tool_name = call.tool_name
        state.metadata["last_tool_arguments"] = str(call.arguments)
        await self._state_cache.set_state(state)

    async def append_tool_result(self, session_id: str, result: ToolResult) -> None:
        """在轮次工作状态中记录工具执行结果。"""
        if self._state_cache is None:
            return
        state = await self._state_cache.get_state(session_id)
        if state is None:
            return
        state.last_tool_status = (
            result.status.value
            if hasattr(result.status, "value")
            else str(result.status)
        )
        state.last_tool_result = dict(result.payload)
        await self._state_cache.set_state(state)

    async def _trim_messages(self, session_id: str) -> None:
        """控制消息列表长度，防止无限增长。"""
        length = await self._redis.llen(_mk(session_id))
        if length and length > _MAX_MESSAGES:
            trim_count = length - _MAX_MESSAGES
            await self._redis.lpop(_mk(session_id), trim_count)


def _decode_message(raw: Any) -> ChatMessage:
    """将 Redis 中存储的 JSON 消息解码为 ChatMessage。"""
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", errors="replace")
    if isinstance(raw, str):
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            data = {"role": "user", "content": str(raw)}
    elif isinstance(raw, dict):
        data = raw
    else:
        data = {"role": "user", "content": str(raw)}

    return ChatMessage(
        role=str(data.get("role", "user")),
        content=str(data.get("content", "")),
    )
