from __future__ import annotations

from typing import Literal

from msgspec import Struct, field


ProcessingSource = Literal["edge", "data_worker"]
RecordStatus = Literal["received", "normalized", "stored", "published", "failed"]


class ClientUserProfileResponse(Struct, kw_only=True):
	"""用户资料响应。

	用于客户端登录后单独拉取个人资料，返回用户展示页需要的基础信息。
	"""

	user_id: str = ""
	username: str = ""
	display_name: str = ""
	name: str = ""
	role: str = "user"
	email: str = ""
	phone: str = ""
	avatar_seed: int = 0


class ClientRegisterResponse(Struct, kw_only=True):
	"""注册响应。

	用于 `POST /v1/client/users/register`，返回注册是否成功，以及失败时的错误码和提示文本。
	常见错误码包括 `username_exists`、`email_exists`、`phone_exists`、`invalid_data`、`data_error`、`unknown_error`。
	"""

	ok: bool = False
	error_code: str = ""
	message: str = ""


class ClientUploadStationSummaryResponse(Struct, kw_only=True):
	"""首页热点站点摘要响应。

	用于首页概览里的 `top_upload_station`，返回站点 ID、站点名和上传数。
	"""
	device_id: str = ""
	device_name: str = ""
	upload_count: int = 0


class ClientLatestUploadSummaryResponse(Struct, kw_only=True):
	"""首页最近上传摘要响应。

	用于首页概览里的 `latest_upload`，返回最近一次上传的站点和时间。
	"""
	device_id: str = ""
	device_name: str = ""
	uploaded_at_ms: int | None = None
	uploaded_at_label: str = ""


class ClientRecordStationOptionResponse(Struct, kw_only=True):
	"""记录页/统计页站点选项响应。

	用于站点筛选下拉框，返回站点 ID、站点名和在线状态。
	"""
	device_id: str = ""
	device_name: str = ""
	online: bool = False
	status: str = "offline"


class ClientBirdRecordResponse(Struct, kw_only=True):
	"""监测记录响应。

	用于记录列表和首页最近记录，返回物种、站点、时间和摘要信息。
	"""
	id: str = ""
	species: str = ""
	scientific_name: str = ""
	captured_at_ms: int = 0
	captured_at_label: str = ""
	device_id: str = ""
	device_name: str = ""
	confidence: float = 0.0
	temperature_c: float | None = None
	humidity_pct: int | None = None
	upload_summary: str = ""
	species_intro: str = ""
	image_url: str = ""
	media_refs: list[str] = field(default_factory=list)
	processing_source: ProcessingSource = "edge"
	model_version: str = ""
	record_status: RecordStatus = "received"
	summary_text: str = ""
	species_entity_id: str = ""
	metadata: dict[str, str] = field(default_factory=dict)


class ClientTrendPointResponse(Struct, kw_only=True):
	"""趋势点响应。

	用于周趋势和时间段统计中的日分布，返回标签、数值和可选日期时间戳。
	"""
	label: str = ""
	value: int = 0
	date_ms: int | None = None


class ClientSpeciesShareResponse(Struct, kw_only=True):
	"""物种占比响应。

	用于统计页物种占比图，返回物种名、数量、占比和可选配色。
	"""
	label: str = ""
	value: int = 0
	ratio: float = 0.0
	species_entity_id: str = ""
	color_hex: str = ""


class ClientPeakDayResponse(Struct, kw_only=True):
	"""峰值日期响应。

	用于时间段统计里的峰值日信息，返回日期标签、峰值数量和日期时间戳。
	"""
	label: str = ""
	value: int = 0
	date_ms: int | None = None


class ClientPeakDeviceSummaryResponse(Struct, kw_only=True):
	"""峰值站点响应。

	用于时间段统计里的 peak_device，返回站点 ID、站点名和记录数。
	"""
	device_id: str = ""
	device_name: str = ""
	record_count: int = 0



class ClientDashboardSnapshotResponse(Struct, kw_only=True):
	"""首页概览响应。

	用于首页接口，承载今日识别、今日上传、站点汇总、热点站点和最近上传记录。
	"""
	today_recognition_count: int = 0
	today_upload_count: int = 0
	online_station_count: int = 0
	active_station_count: int = 0
	top_upload_station: ClientUploadStationSummaryResponse = field(
		default_factory=ClientUploadStationSummaryResponse,
	)
	latest_upload: ClientLatestUploadSummaryResponse = field(
		default_factory=ClientLatestUploadSummaryResponse,
	)
	recent_records: list[ClientBirdRecordResponse] = field(default_factory=list)


class ClientRecordsCursorResponse(Struct, kw_only=True):
	"""记录列表游标响应。

	用于记录页无限滚动，返回一批记录、下一游标和是否还有更多数据。
	"""
	items: list[ClientBirdRecordResponse] = field(default_factory=list)
	next_cursor: str = ""
	has_more: bool = False


class ClientWeeklyTrendResponse(Struct, kw_only=True):
	"""最近七日趋势响应。

	用于统计页折线图，返回时间序列和总数。
	"""
	series: list[ClientTrendPointResponse] = field(default_factory=list)
	total: int = 0



class ClientRangeSummaryResponse(Struct, kw_only=True):
	"""时间段统计响应。

	用于统计页的日分布、物种占比、峰值日期和峰值站点信息。
	"""
	total_count: int = 0
	daily_distribution: list[ClientTrendPointResponse] = field(default_factory=list)
	species_shares: list[ClientSpeciesShareResponse] = field(default_factory=list)
	peak_day: ClientPeakDayResponse = field(default_factory=ClientPeakDayResponse)
	peak_device: ClientPeakDeviceSummaryResponse = field(
		default_factory=ClientPeakDeviceSummaryResponse,
	)
