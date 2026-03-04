from dataclasses import dataclass
from models.models import InferenceResult


@dataclass
class Decision:
    do_local_infer: bool
    upload_event: bool
    mark_server_assist: bool


class DecisionEngine:
    """
    规则目标：
    - 正常：本地推理 + 上传结果（可带图）
    - 弱网/断网：本地落盘，等待补传
    - 置信度低 / 本地推理失败 / 系统高压：上传原始数据并标记 requires_server_assist
    """

    def __init__(self, confidence_threshold: float, high_load_flag_provider):
        self.confidence_threshold = confidence_threshold
        self.high_load_flag_provider = high_load_flag_provider

    def decide_before_infer(self) -> Decision:
        if self.high_load_flag_provider():
            return Decision(
                do_local_infer=False, upload_event=True, mark_server_assist=True
            )
        return Decision(
            do_local_infer=True, upload_event=True, mark_server_assist=False
        )

    def decide_after_infer(
        self, infer_result: InferenceResult, prior: Decision
    ) -> Decision:
        if not infer_result.success:
            prior.mark_server_assist = True
            return prior
        if (infer_result.top1_confidence or 0.0) < self.confidence_threshold:
            prior.mark_server_assist = True
        return prior
