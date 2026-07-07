import time
from uuid import uuid4

from src.iface.agent_resource.session_store import ISessionStore
from src.iface.agent_resource.turn_store import ITurnStore
from src.iface.business.chat_service import IChatService
from src.models.agent.schemas import (
    AgentRequest,
    ImageRef,
    RequestContext,
    RequestMeta,
)
from src.models.agent.session import AgentSession
from src.models.business.chat_req_dto import (
    ChatSendRequest,
    ChatSessionCreateRequest,
    ChatSessionDeleteRequest,
    ChatSessionGetRequest,
    ChatSessionListRequest,
)
from src.models.business.chat_resp_dto import (
    ChatMessageItem,
    ChatSendResponse,
    ChatSessionCreateResponse,
    ChatSessionDeleteResponse,
    ChatSessionDetail,
    ChatSessionListResponse,
    ChatSessionSummary,
)
from src.agent_core.orchestrator.agent import AgentOrchestrator


def _now_ms() -> int:
    return int(time.time() * 1000)


class ChatService(IChatService):
    """聊天服务实现。

    委派 AgentOrchestrator 处理聊天消息，
    通过 ISessionStore / ITurnStore 管理会话生命周期与历史。
    """

    def __init__(
        self,
        orchestrator: AgentOrchestrator,
        session_store: ISessionStore,
        turn_store: ITurnStore,
        *,
        provider_name: str = "",
        model_name: str = "",
    ) -> None:
        if orchestrator is None:
            raise ValueError("orchestrator is required")
        if session_store is None:
            raise ValueError("session_store is required")
        if turn_store is None:
            raise ValueError("turn_store is required")

        self._orchestrator = orchestrator
        self._session_store = session_store
        self._turn_store = turn_store
        self._provider_name = provider_name
        self._model_name = model_name

    async def send_message(self, request: ChatSendRequest) -> ChatSendResponse:
        start = _now_ms()

        # 1. 确保会话存在
        session = await self._session_store.get_session(request.session_id)
        if session is None:
            session = AgentSession(
                session_id=request.session_id,
                user_id=request.user_id,
                status="active",
            )
            await self._session_store.create_session(session)

        # 2. 构造 AgentRequest
        agent_req = self._build_agent_request(request)

        # 3. 记录用户输入轮次
        await self._turn_store.append_turn(
            request.session_id,
            {
                "turn_index": -1,
                "request_id": agent_req.request_id,
                "role": "user",
                "text": request.text,
                "intent_type": "",
                "tool_names": [],
                "image_count": len(request.images),
                "timestamp_ms": _now_ms(),
            },
        )

        # 4. 调用编排器
        agent_resp = await self._orchestrator.run(agent_req)

        # 5. 记录助手回复轮次
        latency_ms = _now_ms() - start
        await self._turn_store.append_turn(
            request.session_id,
            {
                "turn_index": -1,
                "request_id": agent_req.request_id,
                "role": "assistant",
                "text": agent_resp.answer.text or "",
                "intent_type": agent_resp.debug.intent,
                "tool_names": list(agent_resp.debug.tools),
                "timestamp_ms": _now_ms(),
            },
        )

        # 6. 更新会话摘要
        await self._session_store.touch_session(request.session_id)

        # 7. 映射响应
        structured = {}
        if agent_resp.answer.structured:
            structured = dict(agent_resp.answer.structured)

        return ChatSendResponse(
            session_id=request.session_id,
            request_id=agent_req.request_id,
            status=(
                agent_resp.status.value
                if hasattr(agent_resp.status, "value")
                else str(agent_resp.status)
            ),
            text=agent_resp.answer.text or "",
            intent_type=agent_resp.debug.intent,
            tool_names=list(agent_resp.debug.tools),
            structured=structured,
            citations=[
                {"source_id": c.source_id, "title": c.title, "snippet": c.snippet}
                for c in agent_resp.citations
            ],
            latency_ms=latency_ms,
        )

    async def list_sessions(
        self, request: ChatSessionListRequest
    ) -> ChatSessionListResponse:
        sessions = await self._session_store.list_sessions_by_user(
            request.user_id,
            limit=request.limit,
            offset=request.offset,
        )

        items: list[ChatSessionSummary] = []
        for s in sessions:
            # 从轮次记录中获取消息数量和最后文本
            turns = await self._turn_store.list_recent_turns(s.session_id, limit=1)
            last_text = ""
            msg_count = 0
            for t in turns:
                if t.get("role") == "user":
                    last_text = t.get("text", "")
                elif t.get("role") == "assistant":
                    if not last_text:
                        last_text = t.get("text", "")
                msg_count += 1

            title = str(s.metadata.get("title", "")) if s.metadata else ""
            items.append(
                ChatSessionSummary(
                    session_id=s.session_id,
                    title=title,
                    status=s.status,
                    message_count=msg_count or 0,
                    last_text=last_text[:200],
                    created_at_ms=s.created_at_ms or 0,
                    updated_at_ms=s.updated_at_ms or 0,
                )
            )

        return ChatSessionListResponse(
            sessions=items,
            total=len(items),
        )

    async def get_session(self, request: ChatSessionGetRequest) -> ChatSessionDetail:
        session = await self._session_store.get_session(request.session_id)
        if session is None:
            return ChatSessionDetail(
                session_id=request.session_id,
                user_id=request.user_id,
                status="not_found",
            )

        turns = await self._turn_store.list_recent_turns(
            request.session_id, limit=request.message_limit
        )

        messages: list[ChatMessageItem] = []
        for i, t in enumerate(turns):
            messages.append(
                ChatMessageItem(
                    turn_index=i,
                    request_id=t.get("request_id", ""),
                    role=t.get("role", "user"),
                    text=t.get("text", ""),
                    intent_type=t.get("intent_type", ""),
                    tool_names=list(t.get("tool_names") or []),
                    created_at_ms=t.get("timestamp_ms") or 0,
                )
            )

        return ChatSessionDetail(
            session_id=session.session_id,
            user_id=session.user_id,
            status=session.status,
            provider=session.provider or "",
            model=session.model or "",
            messages=messages,
            created_at_ms=session.created_at_ms or 0,
            updated_at_ms=session.updated_at_ms or 0,
        )

    async def delete_session(
        self, request: ChatSessionDeleteRequest
    ) -> ChatSessionDeleteResponse:
        session = await self._session_store.get_session(request.session_id)
        if session is None or session.user_id != request.user_id:
            return ChatSessionDeleteResponse(
                session_id=request.session_id, deleted=False
            )

        await self._session_store.delete_session(request.session_id)
        # turn_store 中的历史数据可保留或由 TTL 清理
        return ChatSessionDeleteResponse(session_id=request.session_id, deleted=True)

    async def create_session(
        self, request: ChatSessionCreateRequest
    ) -> ChatSessionCreateResponse:
        now = _now_ms()
        session_id = str(uuid4())
        metadata = {}
        if request.title:
            metadata["title"] = request.title

        session = AgentSession(
            session_id=session_id,
            user_id=request.user_id,
            status="active",
            created_at_ms=now,
            updated_at_ms=now,
            metadata=metadata,
        )
        await self._session_store.create_session(session)

        return ChatSessionCreateResponse(
            session_id=session_id,
            created_at_ms=now,
        )

    @staticmethod
    def _build_agent_request(request: ChatSendRequest) -> AgentRequest:
        return AgentRequest(
            request_id=str(uuid4()),
            session_id=request.session_id,
            user_id=request.user_id,
            text=request.text,
            images=[
                ImageRef(
                    image_id=img.image_id or f"img_{i}",
                    data=img.data,
                    mime_type=img.mime_type,
                    filename=img.filename,
                    size_bytes=len(img.data),
                )
                for i, img in enumerate(request.images)
            ],
            context=RequestContext(
                locale=request.locale,
                timezone=request.timezone,
            ),
            metadata=RequestMeta(
                trace_id=request.trace_id or str(uuid4()),
            ),
        )
