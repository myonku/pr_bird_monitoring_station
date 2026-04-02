from abc import ABC, abstractmethod

from src.models.workflow.workflow import EdgeEvent


class IEdgeEventUploadCoordinator(ABC):
    """事件流上传协调器接口。"""

    @abstractmethod
    def upload_event(self, event: EdgeEvent) -> bool:
        """上传事件；成功 True，失败 False。"""
        raise NotImplementedError

    @abstractmethod
    def is_upload_channel_ready(self) -> bool:
        """上行通道健康检查。"""
        raise NotImplementedError
