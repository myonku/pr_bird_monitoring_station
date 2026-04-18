# 客户端后端接口草案

版本：0.2.1
状态：草案
适用范围：`bms_app` Flutter 客户端与网关/后端联调

## 1. 目的

本文件用于给客户端和后端提供一份统一的接口草案，目标是：

- 让客户端当前已经拆出来的 `home / records / stats` 数据层可以直接映射到后端接口。
- 让后端可以先按稳定字段语义实现第一版，再逐步细化分页、筛选和扩展字段。
- 保证客户端业务页拿到的响应结构稳定、可序列化、可直接映射到本地展示模型。

本文件是草案，不是最终冻结协议。路径可以在网关层微调，但字段语义、资源边界和错误语义应尽量保持稳定。

## 2. 对接边界

- 客户端只通过网关访问后端。
- 客户端不参与本地密钥 bootstrap。
- 客户端页面中的配色、图标、展示文案和局部排序规则由本地决定，不要求后端返回。
- 客户端运行模式不改变本稿定义的业务响应结构，只影响本地调试、联调和日志标记。
- 当前草案优先覆盖客户端已经实际使用的数据：首页概览、设备列表、记录列表、最近一周趋势、时间段统计。客户端 UI 可以把 `device_name` 继续显示成“站点”。
- 登录、刷新令牌、当前用户等认证相关接口不在本稿范围内；注册作为业务接口纳入本稿。

## 3. 通用约定

### 3.1 建议基础路径

- 建议统一前缀：`/v1/client`
- 首页接口：`/v1/client/home/*`
- 记录接口：`/v1/client/records/*`
- 统计接口：`/v1/client/stats/*`

### 3.2 请求头

建议所有请求携带以下头部：

- `X-Client-Id`：客户端实例标识。
- `X-Device-Id`：设备标识。
- `X-Client-Mode`：客户端运行模式，仅用于日志和灰度观测。
- `X-App-Version`：应用版本号。
- `X-Request-Id`：请求追踪标识。

### 3.3 数据格式

- JSON 字段统一使用 `snake_case`。
- 唯一标识统一使用 UUID v4 字符串。
- 时间字段统一使用 epoch milliseconds，并以 `_ms` 结尾。
- 记录列表接口统一返回 `items`、`next_cursor`、`has_more`。
- 新增字段必须可选，不能破坏已有字段语义。

### 3.4 响应封装

建议所有 HTTP 接口都使用统一封装：

```json
{
  "code": 0,
  "message": "ok",
  "request_id": "d2a9d8ef-1d3b-4e14-8b4f-9d99af6f2f4d",
  "trace_id": "trace-20260412-0001",
  "data": {}
}
```

建议约定：

- `code = 0` 表示成功。
- `message` 用于人类可读提示和日志记录。
- `data` 承载业务载荷。
- 失败时可继续使用统一封装，并配合 HTTP 4xx / 5xx 状态码。

## 4. 业务响应模型

`data_server/src/models/business/client_resp_dto.py` 是本次联调的响应结构来源，后端服务接口直接返回这些 Response 模型，客户端再映射为本地展示模型。

### 4.1 模型对照

- `ClientDashboardSnapshotResponse` 对应客户端首页的 `DashboardSnapshot`
- `ClientBirdRecordResponse` 对应客户端记录页 / 详情页的 `BirdRecord`
- `ClientRecordStationOptionResponse` 对应客户端记录页 / 统计页的 `RecordStationOption`
- `ClientRegisterRequest` 对应客户端注册页提交的注册表单请求
- `ClientRegisterResponse` 对应客户端注册页返回的注册结果
- `ClientTrendPointResponse` 对应客户端的趋势点数据
- `ClientSpeciesShareResponse` 对应客户端统计页的物种占比数据
- `ClientUploadStationSummaryResponse` 对应首页的热点设备摘要
- `ClientPeakDeviceSummaryResponse` 对应统计页的峰值设备摘要
- `ClientLatestUploadSummaryResponse` 对应首页的最近上传摘要
- `ClientRangeSummaryResponse` 对应统计页的时间段汇总结果

说明：

- 响应字段统一使用 `snake_case`。
- 时间字段统一使用 epoch milliseconds，并以 `_ms` 结尾。
- 站点选择统一使用 `device_id` 做筛选，`device_name` 仅用于展示。
- `species_shares` 中的 `color_hex` 为可选展示字段，客户端可忽略并自行映射调色板。

## 5. 业务接口

### 5.0 注册

`POST /v1/client/users/register`

请求结构：`ClientRegisterRequest`

响应结构：`ClientRegisterResponse`

说明：

- 用于注册页提交新账号，用户名必填，邮箱和手机号可选。
- 客户端需要根据 `error_code` 显示对应提示，不直接依赖后端返回文案。
- 建议错误码包括：`username_exists`、`email_exists`、`phone_exists`、`invalid_data`、`data_error`、`unknown_error`。
- `ok=true` 表示注册成功；成功后客户端应返回登录页，不自动登录。

示例：

```json
{
  "ok": false,
  "error_code": "username_exists",
  "message": "用户名已存在"
}
```

### 5.1 用户资料

`GET /v1/client/users/profile?identifier=...`

响应结构：`ClientUserProfileResponse`

说明：

- 用于登录成功后，客户端按登录输入（用户名/邮箱/手机号）单独拉取用户资料。
- 不在登录响应里耦合用户资料，避免认证响应膨胀。

示例：

```json
{
  "user_id": "7a4a7c0c-6b12-4d5f-9a8f-7b2a12d02f19",
  "username": "demo_user",
  "display_name": "测试用户",
  "name": "测试用户",
  "role": "系统演示账号",
  "email": "demo_user@example.com",
  "phone": "138-0000-0000",
  "avatar_seed": 7
}
```

### 5.2 首页概览（聚合接口）

`GET /v1/client/home/summary`

响应结构：`ClientDashboardSnapshotResponse`

示例：

```json
{
  "today_recognition_count": 128,
  "today_upload_count": 26,
  "online_station_count": 9,
  "active_station_count": 6,
  "top_upload_station": {
    "device_id": "2f0b7b69-0b2d-4e3a-9f5f-5db7d0e98711",
    "device_name": "南湖湿地站",
    "upload_count": 52
  },
  "latest_upload": {
    "device_id": "6a2edb8c-9f18-4d9c-bb87-7405a1d5f4d3",
    "device_name": "东堤观察点",
    "uploaded_at_ms": 1712793720000,
    "uploaded_at_label": "2026-04-11 10:42"
  },
  "recent_records": []
}
```

说明：

- 客户端首页只使用这一条聚合接口。
- 后端可在服务内部继续拆分实现，但不再作为客户端依赖面暴露。
- 该接口返回首页所需全部数据，客户端下滑刷新时应直接重新请求它。

### 5.4 站点选项

`GET /v1/client/records/stations`

响应结构：`list[ClientRecordStationOptionResponse]`

示例：

```json
[
  {
    "device_id": "2f0b7b69-0b2d-4e3a-9f5f-5db7d0e98711",
    "device_name": "南湖湿地站",
    "online": true,
    "status": "online"
  }
]
```

说明：

- 该接口服务于记录页和统计页的站点筛选。
- 客户端可将第一项固定渲染为“全部站点”。

### 5.5 记录列表（游标）

`GET /v1/client/records`

建议查询参数：

- `start_at_ms`：开始时间，包含边界。
- `end_at_ms`：结束时间，包含边界。
- `device_id`：设备 ID，可选。
- `keyword`：关键字，可选，建议匹配物种名、学名、摘要。
- `confidence_min`：最低置信度，可选，取值范围 `0~1`。
- `cursor`：游标字符串，首次请求为空。
- `limit`：每次拉取条数，默认 `20`，建议上限 `100`。
- `sort`：默认 `captured_at_ms_desc`。

响应结构：`ClientRecordsCursorResponse`

示例：

```json
{
  "items": [
    {
      "id": "R-2401",
      "species": "白鹭",
      "scientific_name": "Egretta garzetta",
      "captured_at_ms": 1712798400000,
      "captured_at_label": "2026-04-11 09:20",
      "device_id": "2f0b7b69-0b2d-4e3a-9f5f-5db7d0e98711",
      "device_name": "南湖湿地站",
      "confidence": 0.97,
      "temperature_c": 18.4,
      "humidity_pct": 64,
      "upload_summary": "设备自动上传 · 识别结果已同步至业务库",
      "species_intro": "白鹭（Egretta garzetta）...",
      "media_refs": [],
      "processing_source": "edge",
      "model_version": "",
      "record_status": "received",
      "summary_text": "设备自动上传 · 识别结果已同步至业务库",
      "species_entity_id": "",
      "metadata": {}
    }
  ],
  "next_cursor": "20",
  "has_more": true
}
```

说明：

- 记录页使用无限滚动 + 游标续拉，不再使用页码分页。
- 列表项即详情展示数据来源，不再定义单独记录详情接口。
- `image_url` 等详情字段应在记录列表项中直接返回。

### 5.6 最近七日趋势

`GET /v1/client/stats/weekly-trend?days=7&device_id=...`

响应结构：`ClientWeeklyTrendResponse`

示例：

```json
{
  "series": [
    {
      "label": "周一",
      "date_ms": 1712198400000,
      "value": 42
    },
    {
      "label": "周二",
      "date_ms": 1712284800000,
      "value": 54
    }
  ],
  "total": 379
}
```

### 5.7 时间段统计

`GET /v1/client/stats/range-summary`

建议查询参数：

- `start_at_ms`：开始时间，包含边界。
- `end_at_ms`：结束时间，包含边界。
- `device_id`：设备 ID，可选。

建议校验：

- 查询区间最长 30 天。
- 若超过 30 天，建议返回 400 或 422，并给出可读提示。

响应结构：`ClientRangeSummaryResponse`

示例：

```json
{
  "total_count": 128,
  "daily_distribution": [
    {
      "label": "4/1",
      "date_ms": 1711929600000,
      "value": 12
    },
    {
      "label": "4/2",
      "date_ms": 1712016000000,
      "value": 15
    }
  ],
  "species_shares": [
    {
      "label": "白鹭",
      "value": 36,
      "ratio": 0.42,
      "species_entity_id": "",
      "color_hex": "#2A9D8F"
    },
    {
      "label": "灰鹭",
      "value": 24,
      "ratio": 0.28,
      "species_entity_id": "",
      "color_hex": "#E76F51"
    }
  ],
  "peak_day": {
    "label": "4/10",
    "value": 18,
    "date_ms": 1712716800000
  },
  "peak_device": {
    "device_id": "2f0b7b69-0b2d-4e3a-9f5f-5db7d0e98711",
    "device_name": "南湖湿地站",
    "record_count": 54
  }
}
```

说明：

- 这个接口可以支撑统计页的“日分布 + 物种占比 + 峰值信息”。
- `species_shares` 的 `color_hex` 可以由后端返回，也可以留空由客户端映射本地色板。

## 6. 客户端对齐要点

- 记录页改为游标流加载，页面滚动到底部触发下一批拉取。
- 详情页继续直接复用记录列表项数据，不单独发详情请求。
- 统计页仍可通过“游标循环拉全量”或直接调用 `range-summary` 完成聚合展示。

## 7. 错误与兼容

建议客户端重点处理以下 HTTP 场景：

- `401`：未登录、令牌失效或令牌缺失。
- `403`：权限不足。
- `404`：资源不存在。
- `422`：参数校验失败，例如日期范围超过 30 天。
- `429`：触发限流。
- `500`：服务端内部错误。

建议兼容规则：

- 新增字段只能向后兼容扩展。
- 已有字段的语义不能改变。
- 若接口路径需要调整，建议通过网关路由映射兼容，而不是让客户端同时适配多个语义版本。

## 8. no-auth 与 development 差异

- `development`：正常登录、刷新和登出，客户端保存 access token / refresh token。
- `no-auth`：客户端保留登录入口，但不保存 token；请求可以不携带 `Authorization`。
- 两种模式下，页面层收到的数据结构应尽量一致，避免前端出现双套逻辑。
- 如果后端在 `no-auth` 模式下只提供最小业务数据，也建议保持响应封装一致，方便客户端继续复用同一套数据源抽象。

## 9. 建议联调顺序

1. 先打通 `users/profile`（按 identifier 拉用户资料）。
2. 再对齐首页拆分接口（必要时再启用 `home/summary` 聚合）。
3. 接入 `records/stations` 与 `records`（游标流）。
4. 最后接 `stats/weekly-trend` 与 `stats/range-summary`。

这样可以先让“登录后资料加载 + 首页 + 记录流式列表”跑通，再收尾统计页面。
