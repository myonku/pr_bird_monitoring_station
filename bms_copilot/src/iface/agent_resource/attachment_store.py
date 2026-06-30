from __future__ import annotations
from typing import Any
from abc import ABC, abstractmethod


class IAttachmentStore(ABC):
    @abstractmethod
    async def save_attachment_meta(self, meta: dict[str, Any]) -> None: ...
    @abstractmethod
    async def get_attachment_meta(
        self, attachment_id: str
    ) -> dict[str, Any] | None: ...
