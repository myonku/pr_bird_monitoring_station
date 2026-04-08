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
        model_loader: IModelBundleLoader,
        infer: IInferenceModule,
        upload_coordinator: IEdgeEventUploadCoordinator,
        spool: ISpoolStorage,
        decision_engine: DecisionEngine,
        runtime_status_provider: Callable[[], RuntimeStatus],
        event_logger: RuntimeEventLogger | None = None,
    ):
        self.capture = capture
        self.model_loader = model_loader
        self.infer = infer
        self.upload_coordinator = upload_coordinator
        self.spool = spool
        self.decision_engine = decision_engine
        self.runtime_status_provider = runtime_status_provider
        self.event_logger = event_logger

    def _log(self, stage: str, event: str, details: dict | None = None) -> None:
        if self.event_logger is not None:
            self.event_logger.emit(stage=stage, event=event, details=details)

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
            self._log(
                stage="capture",
                event="capture_wait_timeout",
                details={
                    "timeout_sec": capture_timeout_sec,
                },
            )
            return False

        event = EdgeEvent.new(ctx, image)
        self._log(
            stage="capture",
            event="captured",
            details={
                "event_id": event.event_id,
                "image_id": image.image_id,
                "trigger": ctx.trigger_type,
                "width": image.width,
                "height": image.height,
            },
        )

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
        self._log(
            stage="decision",
            event="before_infer_decision",
            details={
                "event_id": event.event_id,
                "do_local_infer": decision.do_local_infer,
                "upload_event": decision.upload_event,
                "server_assist": decision.mark_server_assist,
                "reason": decision.reason,
            },
        )

        if decision.do_local_infer:
            models = self.model_loader.current_bundle()
            result = self.infer.infer_two_stage(image=image, models=models)
            event.local_inference = result
            event.metadata["edge_model_contract_version"] = models.contract.contract_version
            event.metadata["edge_model_package_version"] = models.contract.package_version
            decision = self.decision_engine.decide_after_infer(result, decision)
            event.metadata["decision_after_infer_reason"] = decision.reason
            self._log(
                stage="inference",
                event="local_inference_finished",
                details={
                    "event_id": event.event_id,
                    "success": result.success,
                    "stage": result.stage,
                    "reason": result.reason,
                    "server_assist": decision.mark_server_assist,
                },
            )
        else:
            event.metadata["decision_after_infer_reason"] = "local_inference_skipped"
            self._log(
                stage="inference",
                event="local_inference_skipped",
                details={
                    "event_id": event.event_id,
                    "reason": decision.reason,
                },
            )

        event.requires_server_assist = decision.mark_server_assist

        if decision.upload_event:
            event.metadata["delivery_result"] = "upload_attempted"
            self._log(
                stage="delivery",
                event="upload_attempt",
                details={
                    "event_id": event.event_id,
                    "server_assist": event.requires_server_assist,
                },
            )
            ok = self.upload_coordinator.upload_event(event)
            if not ok:
                event.metadata["delivery_result"] = "upload_failed_spooled"
                record_id = self.spool.put(event)
                self._log(
                    stage="delivery",
                    event="upload_failed_spooled",
                    details={
                        "event_id": event.event_id,
                        "record_id": record_id,
                    },
                )
            else:
                event.metadata["delivery_result"] = "uploaded"
                self._log(
                    stage="delivery",
                    event="upload_succeeded",
                    details={
                        "event_id": event.event_id,
                    },
                )
        else:
            event.metadata["delivery_result"] = "spooled_by_policy"
            record_id = self.spool.put(event)
            self._log(
                stage="delivery",
                event="spooled_by_policy",
                details={
                    "event_id": event.event_id,
                    "record_id": record_id,
                    "reason": decision.reason,
                },
            )

        return True
