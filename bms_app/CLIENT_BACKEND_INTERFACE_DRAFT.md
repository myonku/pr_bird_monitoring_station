# 客户端后端接口草案

版本：0.1.0
状态：草案
适用范围：`bms_app` Flutter 客户端与网关/后端联调

## 1. 目的

本文件用于给客户端和后端提供一份统一的接口草案，目标是：

- 让客户端当前已经拆出来的 `home / records / stats / auth` 数据层可以直接映射到后端接口。
- 让后端可以先按稳定字段语义实现第一版，再逐步细化分页、筛选和扩展字段。
- 保证 `development` 与 `no-auth` 两种模式下的接口语义尽量一致，减少前端分支。

本文件是草案，不是最终冻结协议。路径可以在网关层微调，但字段语义、资源边界和错误语义应尽量保持稳定。

## 2. 对接边界

- 客户端只通过网关访问后端。
- 客户端不参与本地密钥 bootstrap。
- 客户端页面中的配色、图标、展示文案和局部排序规则由本地决定，不要求后端返回。
- `development` 与 `no-auth` 共享同一套业务接口语义；差异主要体现在是否携带认证信息、是否返回可持久化令牌。
- 当前草案优先覆盖客户端已经实际使用的数据：登录、当前用户、首页概览、站点列表、记录列表、记录详情、最近一周趋势、时间段统计。

## 3. 通用约定

### 3.1 建议基础路径

- 建议统一前缀：`/v1/client`
- 认证接口：`/v1/client/auth/*`
- 首页接口：`/v1/client/home/*`
- 记录接口：`/v1/client/records/*`
- 统计接口：`/v1/client/stats/*`

### 3.2 请求头

建议所有请求携带以下头部：

- `Authorization: Bearer <access_token>`：`development` 或正式认证模式下使用。
- `X-Client-Id`：客户端实例标识。
- `X-Device-Id`：设备标识。
- `X-Client-Mode`：`development` 或 `no-auth`。
- `X-App-Version`：应用版本号。
- `X-Request-Id`：请求追踪标识。

### 3.3 数据格式

- JSON 字段统一使用 `snake_case`。
- 唯一标识统一使用 UUID v4 字符串。
- 时间字段统一使用 epoch milliseconds，并以 `_ms` 结尾。
- 列表接口统一返回 `items`、`total`、`page`、`page_size`、`has_more`。
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

## 4. 认证接口

### 4.1 登录

`POST /v1/client/auth/login`

请求体：

```json
{
  "username": "demo_user",
  "password": "******",
  "device_id": "b0e1d8f7-55b6-4c6d-8d5c-b6e1d7c3a0d4",
  "client_mode": "development",
  "app_version": "0.1.0"
}
```

响应体建议包含：

```json
{
  "user": {
    "user_id": "7a4a7c0c-6b12-4d5f-9a8f-7b2a12d02f19",
    "name": "测试用户",
    "role": "系统演示账号",
    "station": "南湖湿地站",
    "phone": "138-0000-0000",
    "avatar_seed": 7
  },
  "access_token": "eyJhbGciOi...",
  "refresh_token": "eyJhbGciOi...",
  "token_type": "Bearer",
  "access_expires_in_ms": 7200000,
  "refresh_expires_in_ms": 2592000000
}
```

说明：

- `no-auth` 部署下可以不强制下发可持久化令牌，但建议尽量保持相同响应结构。
- 如果后端未来需要返回额外会话字段，可追加 `session_id`、`scope`、`issued_at_ms` 等可选字段。

### 4.2 刷新

`POST /v1/client/auth/refresh`

请求体：

```json
{
  "refresh_token": "eyJhbGciOi...",
  "device_id": "b0e1d8f7-55b6-4c6d-8d5c-b6e1d7c3a0d4"
}
```

响应体建议与登录接口保持一致，至少返回：

- `access_token`
- `refresh_token`
- `token_type`
- `access_expires_in_ms`
- `refresh_expires_in_ms`

### 4.3 登出

`POST /v1/client/auth/logout`

请求体建议：

```json
{
  "refresh_token": "eyJhbGciOi...",
  "session_id": "1d8f2b1a-4c7c-4f3d-a3a4-3f73fdc3b1ad"
}
```

响应体建议：

```json
{
  "revoked": true
}
```

### 4.4 当前用户

`GET /v1/client/auth/me`

响应体建议返回登录后的可展示用户信息：

```json
{
  "user": {
    "user_id": "7a4a7c0c-6b12-4d5f-9a8f-7b2a12d02f19",
    "name": "测试用户",
    "role": "系统演示账号",
    "station": "南湖湿地站",
    "phone": "138-0000-0000",
    "avatar_seed": 7
  }
}
```

## 5. 首页接口

### 5.1 首页汇总

`GET /v1/client/home/summary`

这个接口建议一次性返回首页当前需要的全部汇总信息：

```json
{
  "dashboard": {
    "today_recognition_count": 128,
    "today_new_record_count": 26,
    "online_station_count": 9,
    "online_device_count": 18,
    "last_upload_at_ms": 1712793720000,
    "highlighted_bird": "白鹭群在湿地边缘活动"
  },
  "recent_records": [],
  "peak_station": {
    "station_name": "南湖湿地站",
    "record_count": 52
  },
  "total_record_count": 1320,
  "server_time_ms": 1712893720000
}
```

说明：

- 首页当前只需要一组摘要卡片、最近上传提示、热点站点和最近记录。
- `recent_records` 可复用记录摘要结构，不需要返回完整详情。
- `peak_station` 的 `record_count` 可表示今日或当前统计口径下的站点记录数，建议在接口说明里固定口径。

## 6. 记录接口

### 6.1 站点列表

`GET /v1/client/records/stations`

响应体建议：

```json
{
  "stations": [
    {
      "station_id": "2f0b7b69-0b2d-4e3a-9f5f-5db7d0e98711",
      "station_name": "南湖湿地站",
      "online": true,
      "device_count": 4
    }
  ]
}
```

说明：

- 当前客户端只强依赖 `station_name`。
- `station_id`、`online`、`device_count` 都属于建议扩展字段，可选返回。

### 6.2 记录列表

`GET /v1/client/records`

建议查询参数：

- `start_at_ms`：开始时间，包含边界。
- `end_at_ms`：结束时间，包含边界。
- `station_name`：站点名，可选。
- `keyword`：模糊搜索关键字，可选，建议匹配物种名、学名、站点名、摘要。
- `confidence_min`：最低置信度，可选，取值范围 `0~1`。
- `page`：页码，默认 `1`。
- `page_size`：每页条数，默认 `20`，建议上限 `100`。
- `sort`：默认 `captured_at_ms_desc`。

响应体建议：

```json
{
  "items": [
    {
      "id": "R-2401",
      "species": "白鹭",
      "scientific_name": "Egretta garzetta",
      "captured_at_ms": 1712798400000,
      "station_name": "南湖湿地站",
      "confidence": 0.97,
      "temperature_c": 18.4,
      "humidity_pct": 64,
      "upload_summary": "设备自动上传 · 识别结果已同步至业务库",
      "species_intro": "..."
    }
  ],
  "page": 1,
  "page_size": 20,
  "total": 128,
  "has_more": true
}
```

说明：

- 当前客户端的置信度筛选和本地模糊搜索已经先在页面层实现，因此 `confidence_min` 和 `keyword` 可作为后端优化时的扩展能力。
- 若后端暂时不支持这些参数，客户端仍可先在本地过滤，不影响主流程。

### 6.3 记录详情

`GET /v1/client/records/{record_id}`

响应体建议在列表字段基础上补充更详细的信息：

```json
{
  "id": "R-2401",
  "species": "白鹭",
  "scientific_name": "Egretta garzetta",
  "captured_at_ms": 1712798400000,
  "station_name": "南湖湿地站",
  "confidence": 0.97,
  "temperature_c": 18.4,
  "humidity_pct": 64,
  "upload_summary": "设备自动上传 · 识别结果已同步至业务库",
  "species_intro": "白鹭（Egretta garzetta）...",
  "device_id": "6a2edb8c-9f18-4d9c-bb87-7405a1d5f4d3",
  "image_url": "https://example.com/records/R-2401.jpg"
}
```

说明：

- `species_intro` 建议返回，但不是强制项；客户端可保留本地物种简介兜底。
- `image_url`、`device_id`、`latitude`、`longitude` 等字段都可以作为后续扩展，不影响当前页面。

## 7. 统计接口

### 7.1 最近七日趋势

`GET /v1/client/stats/weekly-trend?days=7`

响应体建议：

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

说明：

- 当前客户端只需要最近 7 天的趋势线。
- `label` 可以由后端直接给出，也可以只返回 `date_ms` 后由客户端本地格式化。

### 7.2 时间段统计

`GET /v1/client/stats/range-summary`

建议查询参数：

- `start_at_ms`：开始时间，包含边界。
- `end_at_ms`：结束时间，包含边界。
- `station_name`：站点名，可选。

建议校验：

- 查询区间最长 30 天。
- 若超过 30 天，建议返回 400 或 422，并给出可读提示。

响应体建议：

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
      "ratio": 0.42
    },
    {
      "label": "灰鹭",
      "value": 24,
      "ratio": 0.28
    }
  ],
  "peak_day": {
    "label": "4/10",
    "value": 18
  },
  "peak_station": {
    "station_name": "南湖湿地站",
    "record_count": 54
  }
}
```

说明：

- 这一个接口就足够支持当前统计页下半部分的“日分布柱状图 + 物种占比图”。
- `ratio`、`peak_day`、`peak_station` 都属于建议扩展字段，不影响最小可用版本。

## 8. 公共模型建议

### 8.1 User

建议字段：

- `user_id`
- `name`
- `role`
- `station`
- `phone`
- `avatar_seed`（可选）

### 8.2 DashboardSnapshot

建议字段：

- `today_recognition_count`
- `today_new_record_count`
- `online_station_count`
- `online_device_count`
- `last_upload_at_ms`
- `highlighted_bird`

### 8.3 BirdRecord

建议字段：

- `id`
- `species`
- `scientific_name`
- `captured_at_ms`
- `station_name`
- `confidence`
- `temperature_c`
- `humidity_pct`
- `upload_summary`
- `species_intro`（可选）
- `image_url`（可选）

### 8.4 TrendPoint

建议字段：

- `label`
- `date_ms`
- `value`

### 8.5 SpeciesShare

建议字段：

- `label`
- `value`
- `ratio`（可选）

说明：

- `color` 属于纯展示信息，客户端可以本地映射，不建议强制由后端返回。

## 9. 错误与兼容

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

## 10. no-auth 与 development 差异

- `development`：正常登录、刷新和登出，客户端保存 access token / refresh token。
- `no-auth`：客户端保留登录入口，但不保存 token；请求可以不携带 `Authorization`。
- 两种模式下，页面层收到的数据结构应尽量一致，避免前端出现双套逻辑。
- 如果后端在 `no-auth` 模式下只提供最小业务数据，也建议保持响应封装一致，方便客户端继续复用同一套数据源抽象。

## 11. 建议联调顺序

1. 先打通 `auth/login` 与 `auth/me`。
2. 再接 `home/summary`。
3. 然后接 `records/stations` 与 `records`。
4. 补齐 `records/{record_id}`。
5. 最后接 `stats/weekly-trend` 与 `stats/range-summary`。

这样可以先让客户端从登录到首页跑通，再逐步替换记录页和统计页的数据源。
