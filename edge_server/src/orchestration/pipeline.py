from collections.abc import Callable

from src.iface.workflow_interface import (
    ICaptureModule,
    IInferenceModule,
    IModelBundleLoader,
    ISpoolStorage,
)
from src.iface.upload_interface import IEdgeEventUploadCoordinator
from src.models.workflow.workflow import EdgeEvent
from src.orchestration.decision_engine import DecisionEngine
from src.models.workflow.runtime import RuntimeStatus

class EdgePipeline:
    """边缘端核心流程：捕拍 -> 决策 -> （可选本地推理）-> 上传/入库
    - 捕拍：等待触发并抓拍，获取上下文和图像数据
    - 本地推理：可选，提升响应速度和鲁棒性
    - 决策：根据上下文和推理结果决定是否需要云端辅助
    - 上传/入库：将事件上传到后端或存入本地待上传队列
    """
    def __init__(
        self,
        capture: ICaptureModule,
        model_loader: IModelBundleLoader,
        infer: IInferenceModule,
        upload_coordinator: IEdgeEventUploadCoordinator,
        spool: ISpoolStorage,
        decision_engine: DecisionEngine,
        runtime_status_provider: Callable[[], RuntimeStatus],
    ):
        self.capture = capture
        self.model_loader = model_loader
        self.infer = infer
        self.upload_coordinator = upload_coordinator
        self.spool = spool
        self.decision_engine = decision_engine
        self.runtime_status_provider = runtime_status_provider

    def run_once(self) -> None:
        """执行一次完整的边缘事件处理流程"""
        ctx, image = self.capture.wait_and_capture()
        event = EdgeEvent.new(ctx, image)

        runtime_status = self.runtime_status_provider()
        event.metadata["runtime_status"] = {
            "network_ready": runtime_status.network_ready,
            "high_load": runtime_status.high_load,
            "cpu_percent": runtime_status.cpu_percent,
            "memory_percent": runtime_status.memory_percent,
            "network_reason": runtime_status.network_reason,
            "load_reason": runtime_status.load_reason,
        }

        decision = self.decision_engine.decide_before_infer(runtime_status)
        event.metadata["decision_before_infer_reason"] = decision.reason

        if decision.do_local_infer:
            models = self.model_loader.current_bundle()
            result = self.infer.infer_two_stage(image=image, models=models)
            event.local_inference = result
            event.metadata["edge_model_contract_version"] = models.contract.contract_version
            event.metadata["edge_model_package_version"] = models.contract.package_version
            decision = self.decision_engine.decide_after_infer(result, decision)
            event.metadata["decision_after_infer_reason"] = decision.reason
        else:
            event.metadata["decision_after_infer_reason"] = "local_inference_skipped"

        event.requires_server_assist = decision.mark_server_assist

        if decision.upload_event:
            event.metadata["delivery_result"] = "upload_attempted"
            ok = self.upload_coordinator.upload_event(event)
            if not ok:
                event.metadata["delivery_result"] = "upload_failed_spooled"
                self.spool.put(event)
            else:
                event.metadata["delivery_result"] = "uploaded"
        else:
            event.metadata["delivery_result"] = "spooled_by_policy"
            self.spool.put(event)
