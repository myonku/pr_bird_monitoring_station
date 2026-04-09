from src.iface.orchestration.worker_orchestrator import (
    IWorkerOrchestrator,
    WorkerRequest,
    WorkerResult,
)


class WorkerOrchestratorService(IWorkerOrchestrator):
    """data_worker 顶层编排最小实现骨架。"""

    async def handle_task(self, req: WorkerRequest) -> WorkerResult:
        if req is None:
            raise ValueError("worker request is required")
        raise NotImplementedError("worker orchestrator skeleton not implemented")

    async def handle_inbound_rpc(self, req: WorkerRequest) -> WorkerResult:
        if req is None:
            raise ValueError("worker request is required")
        raise NotImplementedError("worker orchestrator skeleton not implemented")
