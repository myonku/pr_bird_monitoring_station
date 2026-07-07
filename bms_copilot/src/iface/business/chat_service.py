from abc import ABC, abstractmethod

from src.models.business.chat_req_dto import (
    ChatSendRequest,
    ChatSessionCreateRequest,
    ChatSessionDeleteRequest,
    ChatSessionGetRequest,
    ChatSessionListRequest,
)
from src.models.business.chat_resp_dto import (
    ChatSendResponse,
    ChatSessionCreateResponse,
    ChatSessionDeleteResponse,
    ChatSessionDetail,
    ChatSessionListResponse,
)


class IChatService(ABC):
    """聊天服务接口。

    面向客户端提供会话维度的聊天能力。
    内部通过 AgentOrchestrator 完成意图识别 → 工具编排 → 答案合成。
    """

    @abstractmethod
    async def send_message(self, request: ChatSendRequest) -> ChatSendResponse:
        """发送一条聊天消息并获取回复。

        如果 session_id 不存在则自动创建新会话。
        图片（若有）通过 payload 中的 images 字段传输。
        """
        ...

    @abstractmethod
    async def list_sessions(
        self, request: ChatSessionListRequest
    ) -> ChatSessionListResponse:
        """获取指定用户的会话列表，按 updated_at 降序。"""
        ...

    @abstractmethod
    async def get_session(self, request: ChatSessionGetRequest) -> ChatSessionDetail:
        """获取单个会话的完整消息历史。"""
        ...

    @abstractmethod
    async def delete_session(
        self, request: ChatSessionDeleteRequest
    ) -> ChatSessionDeleteResponse:
        """删除指定会话及其所有消息。"""
        ...

    @abstractmethod
    async def create_session(
        self, request: ChatSessionCreateRequest
    ) -> ChatSessionCreateResponse:
        """创建一个新的空会话，返回 session_id。"""
        ...
