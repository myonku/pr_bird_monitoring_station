from collections.abc import Callable
import json

from src.iface.workflow_interface import (
    ICaptureModule,
    IInferenceModule,
    ISpoolStorage,
)
from src.iface.upload_interface import IEdgeEventUploadCoordinator
from src.models.workflow.workflow import EdgeEvent, TwoStageInferenceResult
from src.models.workflow.runtime import Decision, RuntimeStatus
from src.orchestration.decision_engine import DecisionEngine
from src.utils.runtime_logger import RuntimeEventLogger

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
        infer: IInferenceModule,
        upload_coordinator: IEdgeEventUploadCoordinator,
        spool: ISpoolStorage,
        decision_engine: DecisionEngine,
        runtime_status_provider: Callable[[], RuntimeStatus],
        event_logger: RuntimeEventLogger | None = None,
    ):
        self.capture = capture
        self.infer = infer
        self.upload_coordinator = upload_coordinator
        self.spool = spool
        self.decision_engine = decision_engine
        self.runtime_status_provider = runtime_status_provider
        self.event_logger = event_logger

    def _log(self, stage: str, event: str, details: dict | None = None) -> None:
        if self.event_logger is not None:
            self.event_logger.emit(stage=stage, event=event, details=details)

    def _emit_separator(self) -> None:
        if self.event_logger is not None:
            self.event_logger.emit_separator()

    @staticmethod
    def _best_detection_box(result: TwoStageInferenceResult):
        if not result.detection.boxes:
            return None
        return max(result.detection.boxes, key=lambda item: item.confidence)

    def _log_trigger_started(self, event: EdgeEvent) -> None:
        self._log(
            stage="capture",
            event="trigger_started",
            details={
                "event_id": event.event_id,
                "trigger": event.context.trigger_type,
            },
        )

    def _log_inference_summary(
        self,
        event: EdgeEvent,
        decision: Decision,
        result: TwoStageInferenceResult | None,
    ) -> None:
        if result is None:
            details = {
                "event_id": event.event_id,
                "executed": False,
                "success": None,
                "stage": "skipped",
                "detection_label": None,
                "detection_confidence": None,
                "classification_label": None,
                "classification_confidence": None,
                "server_assist": decision.mark_server_assist,
                "reason": decision.reason,
            }
        else:
            best_box = self._best_detection_box(result)
            classification = (
                result.classification
                if result.classification is not None and result.classification.success
                else None
            )
            details = {
                "event_id": event.event_id,
                "executed": True,
                "success": result.success,
                "stage": result.stage,
                "detection_label": best_box.label if best_box else None,
                "detection_confidence": best_box.confidence if best_box else None,
                "classification_label": (
                    classification.top1_label if classification is not None else None
                ),
                "classification_confidence": (
                    classification.top1_confidence if classification is not None else None
                ),
                "server_assist": decision.mark_server_assist,
                "reason": result.reason or decision.reason,
            }

        self._log(stage="inference", event="inference_summary", details=details)

    def _log_trigger_finished(self, event: EdgeEvent, decision: Decision) -> None:
        delivery_result = str(event.metadata.get("delivery_result", "unknown"))
        self._log(
            stage="delivery",
            event="trigger_finished",
            details={
                "event_id": event.event_id,
                "final_result": delivery_result,
                "stored_locally": delivery_result != "uploaded",
                "server_assist": event.requires_server_assist,
                "reason": decision.reason,
            },
        )

    def run_once(self, capture_timeout_sec: float | None = None) -> bool:
        """执行一次完整的边缘事件处理流程。

        返回：
        - True: 本轮成功处理了一条事件
        - False: 本轮仅等待触发超时，未生成事件
        """
        try:
            ctx, image = self.capture.wait_and_capture(timeout_sec=capture_timeout_sec)
        except TimeoutError as exc:
            if str(exc) != "capture_wait_timeout":
                raise
            return False

        event = EdgeEvent.new(ctx, image)
        self._emit_separator()
        self._log_trigger_started(event)

        runtime_status = self.runtime_status_provider()
        event.metadata["runtime_status"] = {
            "network_ready": runtime_status.network_ready,
            "high_load": runtime_status.high_load,
            "cpu_percent": runtime_status.cpu_percent,
            "memory_percent": runtime_status.memory_percent,
            "network_reason": runtime_status.network_reason,
            "load_reason": runtime_status.load_reason,
        }
        event.metadata["runtime_status"] = json.dumps(
            event.metadata["runtime_status"],
            ensure_ascii=False,
        )

        decision = self.decision_engine.decide_before_infer(runtime_status)
        event.metadata["decision_before_infer_reason"] = decision.reason
        inference_result: TwoStageInferenceResult | None = None

        if decision.do_local_infer:
            contract = self.infer.current_contract()
            inference_result = self.infer.infer_two_stage(image=image)
            event.local_inference = inference_result
            event.metadata["edge_model_contract_version"] = contract.contract_version
            event.metadata["edge_model_package_version"] = contract.package_version
            decision = self.decision_engine.decide_after_infer(
                inference_result,
                decision,
            )
            event.metadata["decision_after_infer_reason"] = decision.reason
        else:
            event.metadata["decision_after_infer_reason"] = "local_inference_skipped"

        event.requires_server_assist = decision.mark_server_assist
        self._log_inference_summary(event, decision, inference_result)

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

        self._log_trigger_finished(event, decision)

        return True
