import time
from typing import Any

from src.iface.agent_resource.run_store import IRunStore
from src.models.agent.session import RunRecord


def _now_ms() -> int:
    return int(time.time() * 1000)


class RunStore(IRunStore):
    """基于 Beanie ODM 的运行记录存储。
    """

    def __init__(self, document_model: type[RunRecord] = RunRecord) -> None:
        self._document_model = document_model

    async def start_run(self, run: dict[str, Any]) -> None:
        record = self._document_model(
            run_id=str(run.get("run_id", "")),
            request_id=str(run.get("request_id", "")),
            session_id=str(run.get("session_id", "")),
            user_id=str(run.get("user_id", "")),
            provider=run.get("provider"),
            model=run.get("model"),
            status=run.get("status"),
            intent_type=run.get("intent_type"),
            tool_names=list(run.get("tool_names") or []),
            answer_text=run.get("answer_text"),
            started_at_ms=run.get("started_at_ms") or _now_ms(),
            finished_at_ms=run.get("finished_at_ms"),
            latency_ms=run.get("latency_ms"),
            metadata=dict(run.get("metadata") or {}),
        )
        await record.insert()

    async def finish_run(
        self, run_id: str, status: str, summary: dict[str, Any]
    ) -> None:
        now = _now_ms()
        record = await self._document_model.find_one(self._document_model.run_id == run_id)
        if record is None:
            return
        record.status = status
        record.finished_at_ms = now
        if record.started_at_ms is not None:
            record.latency_ms = now - record.started_at_ms
        if summary.get("answer_text"):
            record.answer_text = summary["answer_text"]
        if summary.get("intent_type"):
            record.intent_type = summary["intent_type"]
        if summary.get("tool_names"):
            record.tool_names = list(summary["tool_names"])
        if summary.get("metadata"):
            record.metadata.update(dict(summary["metadata"]))
        await record.save()

    async def get_run(self, run_id: str) -> dict[str, Any] | None:
        record = await self._document_model.find_one(self._document_model.run_id == run_id)
        if record is None:
            return None
        return {
            "run_id": record.run_id,
            "request_id": record.request_id,
            "session_id": record.session_id,
            "user_id": record.user_id,
            "provider": record.provider,
            "model": record.model,
            "status": record.status,
            "intent_type": record.intent_type,
            "tool_names": list(record.tool_names or []),
            "answer_text": record.answer_text,
            "started_at_ms": record.started_at_ms,
            "finished_at_ms": record.finished_at_ms,
            "latency_ms": record.latency_ms,
            "metadata": dict(record.metadata or {}),
        }
