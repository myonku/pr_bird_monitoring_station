from abc import ABC, abstractmethod

from src.models.business.client_req_dto import (
    ClientUserProfileRequest,
    ClientRegisterRequest,
    ClientHomeSnapshotRequest,
    ClientRangeSummaryRequest,
    ClientRecordsCursorRequest,
    ClientRecordStationOptionsRequest,
    ClientWeeklyTrendRequest,
)
from src.models.business.client_resp_dto import (
    ClientBirdRecordResponse,
    ClientDashboardSnapshotResponse,
    ClientLatestUploadSummaryResponse,
    ClientRecordsCursorResponse,
    ClientRangeSummaryResponse,
    ClientRecordStationOptionResponse,
    ClientUploadStationSummaryResponse,
    ClientRegisterResponse,
    ClientUserProfileResponse,
    ClientWeeklyTrendResponse,
)


class IDataServerService(ABC):
    """客户端业务接口服务抽象。

    这一层承接 users profile / register / home / records / stats 等业务查询，
    不包含登录、刷新令牌等认证接口。
    调用方只传业务载荷，认证头由网关或客户端传输层统一附带，不进入这些 DTO。
    """

    @abstractmethod
    async def get_user_profile(
        self,
        request: ClientUserProfileRequest,
    ) -> ClientUserProfileResponse | None:
        """查询用户资料。

        用于客户端登录成功后按用户名/邮箱/手机号获取用户资料。
        找不到用户时返回 `None`。
        """
        raise NotImplementedError

    @abstractmethod
    async def register_user(
        self,
        request: ClientRegisterRequest,
    ) -> ClientRegisterResponse:
        """注册新用户。

        用于注册页提交用户名、可选邮箱、可选手机号和密码。
        该接口不携带认证头。
        返回 `ok=True` 表示注册成功；否则返回错误码和提示文本供客户端展示。
        """
        raise NotImplementedError

    @abstractmethod
    async def count_today_monitoring_records(self) -> int:
        """获取今日识别数量。"""
        raise NotImplementedError

    @abstractmethod
    async def count_today_upload_records(self) -> int:
        """获取今日上传数量。"""
        raise NotImplementedError

    @abstractmethod
    async def count_online_stations(self) -> int:
        """获取在线站点数量。"""
        raise NotImplementedError

    @abstractmethod
    async def get_today_top_upload_station(self) -> ClientUploadStationSummaryResponse:
        """获取今日上传最活跃站点摘要。"""
        raise NotImplementedError

    @abstractmethod
    async def get_latest_upload_summary(self) -> ClientLatestUploadSummaryResponse:
        """获取最近上传摘要（站点+时间）。"""
        raise NotImplementedError

    @abstractmethod
    async def list_recent_records(self, limit: int = 3) -> list[ClientBirdRecordResponse]:
        """获取首页最近记录摘要列表。"""
        raise NotImplementedError

    @abstractmethod
    async def get_dashboard_snapshot(
        self,
        request: ClientHomeSnapshotRequest | None = None,
    ) -> ClientDashboardSnapshotResponse:
        """获取首页概览数据。

        这是聚合接口，可由上面的拆分接口组合得到，用于减少客户端并发请求数。
        """
        raise NotImplementedError

    @abstractmethod
    async def list_record_station_options(
        self,
        request: ClientRecordStationOptionsRequest | None = None,
    ) -> list[ClientRecordStationOptionResponse]:
        """列出记录页/统计页的站点筛选选项。

        返回可用于下拉框展示的站点 ID、站点名和在线状态。
        """
        raise NotImplementedError

    @abstractmethod
    async def list_records_by_cursor(
        self,
        request: ClientRecordsCursorRequest,
    ) -> ClientRecordsCursorResponse:
        """按游标查询记录列表。

        返回记录列表分批数据，供记录页无限滚动使用。
        """
        raise NotImplementedError

    @abstractmethod
    async def get_weekly_trend(
        self,
        request: ClientWeeklyTrendRequest,
    ) -> ClientWeeklyTrendResponse:
        """获取最近七日趋势。

        返回折线图所需的时间序列和值汇总。
        """
        raise NotImplementedError

    @abstractmethod
    async def get_range_summary(
        self,
        request: ClientRangeSummaryRequest,
    ) -> ClientRangeSummaryResponse:
        """获取时间段统计结果。

        返回日分布、物种占比、峰值日期和峰值站点信息，供统计页使用。
        """
        raise NotImplementedError



