from abc import ABC, abstractmethod
from collections.abc import Iterable

from src.models.models import CaptureContext, EdgeEvent, ImagePayload, InferenceResult


class ICaptureModule(ABC):
    """捕拍模块接口；负责等待触发并抓拍，提供捕拍上下文和图像数据等信息"""

    @abstractmethod
    def wait_and_capture(
        self, timeout_sec: float | None = None
    ) -> tuple[CaptureContext, ImagePayload]:
        """阻塞等待触发并抓拍，返回上下文 + 图像"""
        raise NotImplementedError


class IInferenceModule(ABC):
    """推理模块接口；负责加载和执行边缘端的推理模型，提供推理结果和置信度等信息"""

    @abstractmethod
    def infer(self, image: ImagePayload) -> InferenceResult:
        raise NotImplementedError

    @abstractmethod
    def current_model_version(self) -> str:
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
    """统一上行通道接口；实现类可内部切换 Kafka/HTTP/gRPC 等传输方式"""

    @abstractmethod
    def upload(self, event: EdgeEvent) -> bool:
        """统一上行通道；成功 True，失败 False"""
        raise NotImplementedError

    @abstractmethod
    def is_connection_ready(self) -> bool:
        raise NotImplementedError

class ITransportClient(ABC):
    """底层传输客户端接口；提供发送数据和健康检查等功能"""

    @abstractmethod
    def send(self, payload: dict, image_bytes: bytes) -> bool:
        """发送数据；成功 True，失败 False"""
        raise NotImplementedError

    @abstractmethod
    def healthcheck(self) -> bool:
        """检查连接是否可用"""
        raise NotImplementedError

class IModelManager(ABC):
    """模型管理接口；负责检查/更新边缘端使用的推理模型版本，提供当前模型路径等信息"""

    @abstractmethod
    def get_active_model_path(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def get_active_model_version(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def try_apply_remote_update(self) -> bool:
        """轮询服务端是否有新模型，有则下载+校验+切换"""
        raise NotImplementedError
