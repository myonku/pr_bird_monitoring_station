from models.models import EdgeEvent
from edge_server.src.interface import ICaptureModule, IInferenceModule, ISpoolStorage, IUploader
from orchestration.decision_engine import DecisionEngine


class EdgePipeline:
    """边缘端核心流程：捕拍 -> （本地推理）-> 决策 -> 上传/入库
    - 捕拍：等待触发并抓拍，获取上下文和图像数据
    - 本地推理：可选，提升响应速度和鲁棒性
    - 决策：根据上下文和推理结果决定是否需要云端辅助
    - 上传/入库：将事件上传到后端或存入本地待上传队列
    """
    def __init__(
        self,
        capture: ICaptureModule,
        infer: IInferenceModule,
        uploader: IUploader,
        spool: ISpoolStorage,
        decision_engine: DecisionEngine,
    ):
        self.capture = capture
        self.infer = infer
        self.uploader = uploader
        self.spool = spool
        self.decision_engine = decision_engine

    def run_once(self) -> None:
        """执行一次完整的边缘事件处理流程"""
        ctx, image = self.capture.wait_and_capture()
        event = EdgeEvent.new(ctx, image)

        decision = self.decision_engine.decide_before_infer()

        if decision.do_local_infer:
            result = self.infer.infer(image)
            event.local_inference = result
            event.metadata["edge_model_version"] = self.infer.current_model_version()
            decision = self.decision_engine.decide_after_infer(result, decision)

        event.requires_server_assist = decision.mark_server_assist

        if decision.upload_event:
            ok = self.uploader.upload(event)
            if not ok:
                self.spool.put(event)
        else:
            self.spool.put(event)
