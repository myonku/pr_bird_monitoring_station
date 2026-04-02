from src.models.workflow.workflow import TwoStageInferenceResult
from src.models.workflow.runtime import RuntimeStatus, Decision


class DecisionEngine:
    """
    规则目标：
    - 正常：本地推理 + 上传结果（可带图）
    - 弱网/断网：本地落盘，等待补传
    - 置信度低 / 本地推理失败 / 系统高压：上传原始数据并标记 requires_server_assist
    """

    def __init__(
        self,
        enable_local_inference: bool,
        confidence_threshold: float,
    ):
        self.enable_local_inference = enable_local_inference
        self.confidence_threshold = confidence_threshold

    def decide_before_infer(self, runtime_status: RuntimeStatus) -> Decision:
        if not runtime_status.network_ready:
            # 弱网/断网时先落本地缓存，待网络恢复后续传。
            return Decision(
                do_local_infer=self.enable_local_inference
                and not runtime_status.high_load,
                upload_event=False,
                mark_server_assist=not self.enable_local_inference,
                reason=runtime_status.network_reason or "network_not_ready",
            )

        if runtime_status.high_load:
            return Decision(
                do_local_infer=False,
                upload_event=True,
                mark_server_assist=True,
                reason=runtime_status.load_reason or "high_load",
            )

        if not self.enable_local_inference:
            return Decision(
                do_local_infer=False,
                upload_event=True,
                mark_server_assist=True,
                reason="local_inference_disabled",
            )

        return Decision(
            do_local_infer=True,
            upload_event=True,
            mark_server_assist=False,
            reason="normal_path",
        )

    def decide_after_infer(
        self,
        infer_result: TwoStageInferenceResult,
        prior: Decision,
    ) -> Decision:
        # 检测失败：建议服务端接管。
        if infer_result.stage == "detector_failed":
            prior.mark_server_assist = True
            prior.reason = "detector_failed"
            return prior

        # 未检测到目标：本地提前退出，不强制服务端识别。
        if infer_result.stage == "detected_only":
            prior.mark_server_assist = False
            prior.reason = "detected_only"
            return prior

        if not infer_result.success:
            prior.mark_server_assist = True
            prior.reason = "inference_failed"
            return prior

        top1 = (
            infer_result.classification.top1_confidence
            if infer_result.classification
            else None
        )
        if (top1 or 0.0) < self.confidence_threshold:
            prior.mark_server_assist = True
            prior.reason = "low_confidence"
        else:
            prior.reason = "local_inference_confident"
        return prior
