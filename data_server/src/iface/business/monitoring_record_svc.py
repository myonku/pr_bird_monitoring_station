from abc import ABC, abstractmethod
from datetime import date
from uuid import UUID

from src.models.business.event import MonitoringRecord


class IMonitoringRecordManager(ABC):
	"""监测记录的 CRUD 管理接口。"""

	@abstractmethod
	async def get_by_id(self, record_id: UUID) -> MonitoringRecord | None:
		"""根据记录 ID 获取记录。"""
		raise NotImplementedError

	@abstractmethod
	async def list_recent_week(
		self,
		device_entity_id: UUID | None = None,
	) -> list[MonitoringRecord]:
		"""列出最近一周的监测记录，可选按站点过滤。"""
		raise NotImplementedError

	@abstractmethod
	async def list_by_day_range(
		self,
		start_day: date,
		end_day: date,
		device_entity_id: UUID | None = None,
	) -> list[MonitoringRecord]:
		"""按自然日范围查询监测记录，可选按站点过滤。"""
		raise NotImplementedError

	@abstractmethod
	async def list_all(self) -> list[MonitoringRecord]:
		"""列出当前所有记录。"""
		raise NotImplementedError

	@abstractmethod
	async def create(self, record: MonitoringRecord) -> MonitoringRecord:
		"""创建新的监测记录。"""
		raise NotImplementedError

	@abstractmethod
	async def update(self, record: MonitoringRecord) -> MonitoringRecord | None:
		"""更新已有监测记录。"""
		raise NotImplementedError

	@abstractmethod
	async def delete(self, record_id: UUID) -> bool:
		"""删除监测记录。"""
		raise NotImplementedError

	@abstractmethod
	async def count_today_monitoring_records(self) -> int:
		"""统计当日 0 点后的监测记录数量。"""
		raise NotImplementedError

	@abstractmethod
	async def list_latest_three(self) -> list[MonitoringRecord]:
		"""获取最新的三条监测记录。"""
		raise NotImplementedError

	@abstractmethod
	async def list_recent_week_daily_counts(self) -> list[dict[str, object]]:
		"""获取最近一周每天的监测记录数量。"""
		raise NotImplementedError
