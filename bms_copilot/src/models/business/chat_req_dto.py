from msgspec import Struct, field


class ChatImageRef(Struct, kw_only=True):
    """聊天请求中携带的图片引用。"""

    image_id: str = ""
    data: bytes = b""
    mime_type: str = "image/jpeg"
    filename: str = ""


class ChatSendRequest(Struct, kw_only=True):
    """发送聊天消息请求。

    对应 route_key: ``business.chat.send``
    """

    session_id: str
    user_id: str
    text: str
    images: list[ChatImageRef] = field(default_factory=list)
    locale: str = "zh-CN"
    timezone: str = "Asia/Shanghai"
    trace_id: str = ""


class ChatSessionListRequest(Struct, kw_only=True):
    """获取用户会话列表请求。

    对应 route_key: ``business.chat.sessions.list``
    """

    user_id: str
    limit: int = 20
    offset: int = 0


class ChatSessionGetRequest(Struct, kw_only=True):
    """获取单个会话详情请求。

    对应 route_key: ``business.chat.sessions.get``
    """

    session_id: str
    user_id: str
    message_limit: int = 50


class ChatSessionDeleteRequest(Struct, kw_only=True):
    """删除会话请求。

    对应 route_key: ``business.chat.sessions.delete``
    """

    session_id: str
    user_id: str


class ChatSessionCreateRequest(Struct, kw_only=True):
    """创建新会话请求。

    对应 route_key: ``business.chat.sessions.create``
    """

    user_id: str
    title: str = ""
