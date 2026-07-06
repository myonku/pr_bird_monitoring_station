import time

from src.iface.agent_resource.usage_store import IUsageStore
from src.models.agent.usage import SessionUsageSummary, UsageRecord


class UsageStore(IUsageStore):
    """基于 Beanie ODM 的用量记录存储。"""

    def __init__(self, document_model: type[UsageRecord] = UsageRecord) -> None:
        self._document_model = document_model

    async def record_usage(self, usage: UsageRecord) -> None:
        if not usage.created_at_ms:
            usage.created_at_ms = int(time.time() * 1000)
        await usage.insert()

    async def list_by_run(self, run_id: str) -> list[UsageRecord]:
        return (
            await self._document_model.find(self._document_model.run_id == run_id)
            .sort(str(self._document_model.created_at_ms))
            .to_list()
        )

    async def list_by_session(self, session_id: str) -> list[UsageRecord]:
        return (
            await self._document_model.find(
                self._document_model.session_id == session_id
            )
            .sort(str(self._document_model.created_at_ms))
            .to_list()
        )

    async def aggregate_by_session(self, session_id: str) -> SessionUsageSummary | None:
        records = await self._document_model.find(
            self._document_model.session_id == session_id
        ).to_list()
        if not records:
            return None

        summary = SessionUsageSummary(session_id=session_id)
        for r in records:
            summary.total_calls += 1
            summary.total_prompt_tokens += r.prompt_tokens or 0
            summary.total_completion_tokens += r.completion_tokens or 0
            summary.total_tokens += r.total_tokens or 0

            stage = r.stage or "unknown"
            summary.by_stage[stage] = summary.by_stage.get(stage, 0) + (
                r.total_tokens or 0
            )

            model = r.model or "unknown"
            summary.by_model[model] = summary.by_model.get(model, 0) + (
                r.total_tokens or 0
            )

        return summary
