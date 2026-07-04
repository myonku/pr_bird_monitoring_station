from __future__ import annotations

from typing import Protocol

from src.models.agent.snapshot import AttachmentMeta


class IAttachmentStore(Protocol):
    async def save_attachment_meta(self, meta: AttachmentMeta) -> None: ...

    async def get_attachment_meta(self, attachment_id: str) -> AttachmentMeta | None: ...
