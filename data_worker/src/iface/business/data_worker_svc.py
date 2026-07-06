from abc import ABC, abstractmethod
from dataclasses import dataclass

from src.models.business.event_req_dto import EdgeEventUploadRequest

from src.models.business.event import (
    EdgeEventEnvelope,
    MonitoringRecord,
    ProcessingSource,
)
from src.models.inference.workflow import TwoStageInferenceResult


@dataclass(slots=True, kw_only=True)
class EdgeEventProcessingResult:
    """边缘事件处理的统一结果摘要。"""

    request: EdgeEventUploadRequest
    envelope: EdgeEventEnvelope
    processing_source: ProcessingSource
    stage_a_enter_stage_b: bool
    stage_a_reason: str = ""
    inference_result: TwoStageInferenceResult | None = None
    monitoring_record: MonitoringRecord | None = None


class IDataWorkerService(ABC):
    """数据处理模块的统一业务流水线接口。

    该接口只负责把外部请求交给业务层统一流程处理，不承担通信层职责。
    """

    @abstractmethod
    async def handle_edge_upload(
        self,
        request: EdgeEventUploadRequest,
    ) -> EdgeEventProcessingResult:
        """处理边缘端上传请求并执行 A/B 阶段流水线。

        返回值承载本次处理的统一结果摘要：
        - monitoring_record 非空：请求进入阶段 B 并成功沉淀。
        - monitoring_record 为空：请求在阶段 A 被判定丢弃。
        """
        raise NotImplementedError
