from src.interface import (
    ICaptureModule,
    IInferenceModule,
    IModelBundleLoader,
    ISpoolStorage,
    IUploader,
)
from src.models.models import EdgeEvent
from src.orchestration.decision_engine import DecisionEngine


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
        model_loader: IModelBundleLoader,
        infer: IInferenceModule,
        uploader: IUploader,
        spool: ISpoolStorage,
        decision_engine: DecisionEngine,
    ):
        self.capture = capture
        self.model_loader = model_loader
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
            models = self.model_loader.current_bundle()
            result = self.infer.infer_two_stage(image=image, models=models)
            event.local_inference = result
            event.metadata["edge_model_contract_version"] = models.contract.contract_version
            event.metadata["edge_model_package_version"] = models.contract.package_version
            decision = self.decision_engine.decide_after_infer(result, decision)

        event.requires_server_assist = decision.mark_server_assist

        if decision.upload_event:
            ok = self.uploader.upload(event)
            if not ok:
                self.spool.put(event)
        else:
            self.spool.put(event)
