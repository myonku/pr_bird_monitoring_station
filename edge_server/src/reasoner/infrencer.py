from src.models.models import ImagePayload, InferenceResult
from edge_server.src.interface import IInferenceModule


class InfrenceModule(IInferenceModule):
    """边缘端推理模块接口定义，提供本地推理功能"""
    def infer(self, image: ImagePayload) -> InferenceResult:
        """对给定的图像进行本地推理，返回推理结果"""
        raise NotImplementedError
