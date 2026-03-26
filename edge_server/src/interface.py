from abc import ABC, abstractmethod
from collections.abc import Iterable

from src.models.models import (
    CaptureContext,
    ClassificationResult,
    DetectionResult,
    EdgeEvent,
    EdgeModelContract,
    ImagePayload,
    LoadedModelBundle,
    TwoStageInferenceResult,
)


class ICaptureModule(ABC):
    """捕拍模块接口；负责等待触发并抓拍，提供捕拍上下文和图像数据等信息"""

    @abstractmethod
    def wait_and_capture(
        self, timeout_sec: float | None = None
    ) -> tuple[CaptureContext, ImagePayload]:
        """阻塞等待触发并抓拍，返回上下文 + 图像"""
        raise NotImplementedError


class IInferenceModule(ABC):
    """推理模块接口；仅负责推理逻辑，不负责模型加载。"""

    @abstractmethod
    def detect(self, image: ImagePayload, models: LoadedModelBundle) -> DetectionResult:
        raise NotImplementedError

    @abstractmethod
    def classify(
        self,
        image: ImagePayload,
        detection: DetectionResult,
        models: LoadedModelBundle,
    ) -> ClassificationResult:
        raise NotImplementedError

    @abstractmethod
    def infer_two_stage(
        self,
        image: ImagePayload,
        models: LoadedModelBundle,
    ) -> TwoStageInferenceResult:
        """先检测后分类，检测失败时提前退出。"""
        raise NotImplementedError


class IModelBundleLoader(ABC):
    """模型加载模块接口；一次加载检测和分类模型，并暴露统一句柄。"""

    @abstractmethod
    def load(self, contract: EdgeModelContract) -> LoadedModelBundle:
        raise NotImplementedError

    @abstractmethod
    def current_bundle(self) -> LoadedModelBundle:
        raise NotImplementedError

    @abstractmethod
    def current_contract(self) -> EdgeModelContract:
        raise NotImplementedError


class ISpoolStorage(ABC):
    """本地待上传事件存储接口；实现类可基于文件系统、SQLite、轻量级 KV 存储等"""

    @abstractmethod
    def put(self, event: EdgeEvent) -> str:
        """写入本地缓存，返回本地记录ID"""
        raise NotImplementedError

    @abstractmethod
    def peek_batch(self, limit: int) -> Iterable[tuple[str, EdgeEvent]]:
        """读取待补传记录（不删除）"""
        raise NotImplementedError

    @abstractmethod
    def ack(self, record_id: str) -> None:
        """补传成功后确认删除/标记完成"""
        raise NotImplementedError

    @abstractmethod
    def mark_retry(self, record_id: str, reason: str) -> None:
        raise NotImplementedError


class IUploader(ABC):
    """上行接口；边缘端统一使用 HTTP 上传。"""

    @abstractmethod
    def upload(self, event: EdgeEvent) -> bool:
        """上传事件；成功 True，失败 False。"""
        raise NotImplementedError

    @abstractmethod
    def is_connection_ready(self) -> bool:
        raise NotImplementedError


class IHttpTransportClient(ABC):
    """HTTP 传输客户端接口。"""

    @abstractmethod
    def send(self, payload: dict, image_bytes: bytes) -> bool:
        """通过 HTTP POST 发送数据；成功 True，失败 False。"""
        raise NotImplementedError

    @abstractmethod
    def healthcheck(self) -> bool:
        """通过 HTTP 健康检查确认连接可用。"""
        raise NotImplementedError


class IModelManager(ABC):
    """模型管理接口；负责双模型包版本管理和更新。"""

    @abstractmethod
    def get_active_contract(self) -> EdgeModelContract:
        raise NotImplementedError

    @abstractmethod
    def get_active_model_paths(self) -> dict[str, str]:
        raise NotImplementedError

    @abstractmethod
    def get_active_package_version(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def try_apply_remote_update(self) -> bool:
        """轮询服务端是否有新模型包，有则下载+校验+切换。"""
        raise NotImplementedError
