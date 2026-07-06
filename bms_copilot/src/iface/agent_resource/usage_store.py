from abc import ABC, abstractmethod

from src.models.agent.usage import SessionUsageSummary, UsageRecord


class IUsageStore(ABC):
    @abstractmethod
    async def record_usage(self, usage: UsageRecord) -> None: ...

    @abstractmethod
    async def list_by_run(self, run_id: str) -> list[UsageRecord]: ...

    @abstractmethod
    async def list_by_session(self, session_id: str) -> list[UsageRecord]: ...

    @abstractmethod
    async def aggregate_by_session(
        self, session_id: str
    ) -> SessionUsageSummary | None: ...
