from src.iface.agent_resource.tool_trace_store import IToolTraceStore
from src.models.agent.tool_record import ToolCallRecord, ToolResultRecord


class ToolTraceStore(IToolTraceStore):
    """工具调用记录与结果的持久化存储，基于MongoDB/Beanie。"""

    def __init__(
        self,
        call_model: type[ToolCallRecord] = ToolCallRecord,
        result_model: type[ToolResultRecord] = ToolResultRecord,
    ) -> None:
        self._call_model = call_model
        self._result_model = result_model

    async def save_tool_call(self, record: ToolCallRecord) -> None:
        await record.insert()

    async def save_tool_result(self, record: ToolResultRecord) -> None:
        await record.insert()

    async def list_tool_records(
        self, run_id: str
    ) -> list[ToolCallRecord | ToolResultRecord]:
        call_records = await self._call_model.find(
            self._call_model.run_id == run_id
        ).to_list()
        result_records = await self._result_model.find(
            self._result_model.run_id == run_id
        ).to_list()
        return call_records + result_records
