from abc import ABC, abstractmethod

from src.models.inference.config import InferenceConfig
from src.models.inference.workflow import (
    ClassificationResult,
    DetectionResult,
    InferenceImagePayload,
    InferenceModelContract,
    LoadedInferenceBundle,
    TwoStageInferenceResult,
)


class IInferenceModule(ABC):
    """推理模块接口；仅负责推理逻辑，不负责模型加载。"""

    @abstractmethod
    def detect(
        self,
        image: InferenceImagePayload,
    ) -> DetectionResult:
        raise NotImplementedError

    @abstractmethod
    def classify(
        self,
        image: InferenceImagePayload,
        detection: DetectionResult,
    ) -> ClassificationResult:
        raise NotImplementedError

    @abstractmethod
    def infer_two_stage(
        self,
        image: InferenceImagePayload,
    ) -> TwoStageInferenceResult:
        raise NotImplementedError


class IModelBundleLoader(ABC):
    """模型加载模块接口；从配置中加载检测和分类模型，并暴露统一句柄。"""

    @abstractmethod
    def load(self, config: InferenceConfig) -> LoadedInferenceBundle:
        raise NotImplementedError

    @abstractmethod
    def current_bundle(self) -> LoadedInferenceBundle:
        raise NotImplementedError

    @abstractmethod
    def current_contract(self) -> InferenceModelContract:
        raise NotImplementedError
