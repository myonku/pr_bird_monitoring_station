from __future__ import annotations

from typing import Literal

from msgspec import Struct


class ClientUserProfileRequest(Struct, kw_only=True):
	"""用户资料查询请求模型。

	用于客户端在登录成功后，根据登录输入的标识（用户名/邮箱/手机号）拉取用户资料。
	"""

	identifier: str = ""


class ClientRegisterRequest(Struct, kw_only=True):
	"""注册请求模型。

	用于 `POST /v1/client/users/register`，承载注册页提交的用户名、可选邮箱、可选手机号和密码。
	"""

	username: str = ""
	email: str = ""
	phone: str = ""
	password: str = ""


class ClientHomeSnapshotRequest(Struct, kw_only=True):
	"""首页概览请求模型。

	用于 `GET /v1/client/home/summary`，当前仅保留 `device_id` 作为可选过滤/观测字段。
	"""

	device_id: str | None = None


class ClientRecordStationOptionsRequest(Struct, kw_only=True):
	"""记录页站点选项请求模型。

	用于 `GET /v1/client/records/stations`，可控制是否包含离线站点。
	"""

	include_offline: bool | None = None


class ClientRecordsCursorRequest(Struct, kw_only=True):
	"""记录列表游标请求模型。

	用于 `GET /v1/client/records`，承载时间范围、站点筛选与游标参数。
	"""

	start_at_ms: int | None = None
	end_at_ms: int | None = None
	device_id: str | None = None
	keyword: str | None = None
	confidence_min: float | None = None
	cursor: str | None = None
	limit: int = 20
	sort: Literal["captured_at_ms_desc"] = "captured_at_ms_desc"


class ClientWeeklyTrendRequest(Struct, kw_only=True):
	"""最近七日趋势请求模型。

	用于 `GET /v1/client/stats/weekly-trend`，可指定天数和设备筛选条件。
	"""

	days: int = 7
	device_id: str | None = None


class ClientRangeSummaryRequest(Struct, kw_only=True):
	"""时间段统计请求模型。

	用于 `GET /v1/client/stats/range-summary`，承载时间区间和可选设备筛选条件。
	"""

	start_at_ms: int = 0
	end_at_ms: int = 0
	device_id: str | None = None
