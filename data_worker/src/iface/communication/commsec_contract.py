from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from msgspec import Struct

from src.models.commsec.commsec import EncryptedMessageMeta

if TYPE_CHECKING:
    from src.iface.communication.commsec_channel_manager import ECDHEHandshakeInitRequest, SecureChannelQuery


@dataclass(slots=True, kw_only=True)
class SecureChannelEnsureRequest:
    """主动通信方出站前确保通道可用的共享请求契约。"""

    query: SecureChannelQuery
    handshake_init: ECDHEHandshakeInitRequest | None = None
    require_active: bool = True
    force_rehandshake: bool = False


class ChannelEncryptResult(Struct, kw_only=True):
    """通过安全通道进行载荷加密的结果契约。"""

    ciphertext: str
    meta: EncryptedMessageMeta
