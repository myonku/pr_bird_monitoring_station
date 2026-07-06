from abc import ABC, abstractmethod
from uuid import UUID

from src.models.business.event import EdgeEventEnvelope


class IEnvelopeManager(ABC):
    """边缘事件信封的 CRUD 管理接口。"""

    @abstractmethod
    async def get_by_id(self, event_id: UUID) -> EdgeEventEnvelope | None:
        """根据事件 ID 获取信封。"""
        raise NotImplementedError

    @abstractmethod
    async def list_all(self) -> list[EdgeEventEnvelope]:
        """列出当前所有信封。"""
        raise NotImplementedError

    @abstractmethod
    async def create(self, envelope: EdgeEventEnvelope) -> EdgeEventEnvelope:
        """创建新的边缘事件信封。"""
        raise NotImplementedError

    @abstractmethod
    async def update(self, envelope: EdgeEventEnvelope) -> EdgeEventEnvelope | None:
        """更新已有边缘事件信封。"""
        raise NotImplementedError

    @abstractmethod
    async def delete(self, event_id: UUID) -> bool:
        """删除边缘事件信封。"""
        raise NotImplementedError

    @abstractmethod
    async def count_today_upload_records(self) -> int:
        """统计当日 0 点后的上传记录数量。"""
        raise NotImplementedError

    @abstractmethod
    async def get_today_top_upload_site(self) -> dict[str, object] | None:
        """获取当日上传记录最多的站点，返回设备 id、name 和数量。"""
        raise NotImplementedError

    @abstractmethod
    async def get_latest_upload_summary(self) -> dict[str, object] | None:
        """获取最新一条上传记录的时间和站点信息。"""
        raise NotImplementedError
