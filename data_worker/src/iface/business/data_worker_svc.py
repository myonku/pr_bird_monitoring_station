from abc import ABC, abstractmethod

from src.models.business.event_req_dto import EdgeEventUploadRequest
from src.models.business.data import MonitoringRecord


class IDataWorkerService(ABC):
    """数据处理模块的统一业务流水线接口。

    该接口只负责把外部请求交给业务层统一流程处理，不承担通信层职责。
    """

    @abstractmethod
    async def handle_edge_upload(
        self,
        request: EdgeEventUploadRequest,
    ) -> MonitoringRecord | None:
        """处理边缘端上传请求并执行 A/B 阶段流水线。

        返回值：
        - MonitoringRecord：请求进入阶段 B 并成功沉淀。
        - None：请求在阶段 A 被判定丢弃。
        """
        raise NotImplementedError
