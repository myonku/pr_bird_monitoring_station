from __future__ import annotations
from typing import Any
from abc import ABC, abstractmethod


class IUsageStore(ABC):
    @abstractmethod
    async def save_provider_usage(self, usage: dict[str, Any]) -> None: ...
    @abstractmethod
    async def list_usage_by_run(self, run_id: str) -> list[dict[str, Any]]: ...
