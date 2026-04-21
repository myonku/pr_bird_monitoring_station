# 全局外部接口清单设计说明

版本：1.0.0
状态：Baseline
适用范围：`bms_app` 客户端、`edge_server` 边缘端、`gateway` 对外 HTTP 接口

## 1. 文档目的

本文件统一收敛客户端与边缘端的外部接口清单，按以下两条主线组织：

- 业务接口：面向页面数据、业务上传和运行观测。
- 认证接口：面向登录、刷新、bootstrap、token 生命周期维护。

本文件只定义对外可见的接口边界与字段语义，不展开各模块内部实现细节。所有外部请求默认经由 `gateway` 进入后端；认证相关请求再由 `gateway` 转发到 `certification_server`。

## 2. 全局约定

- 唯一标识统一使用 UUID v4 字符串。
- 时间字段统一使用 epoch milliseconds，并以 `_ms` 结尾。
- JSON 字段统一使用 `snake_case`。
- 除注册、登录与刷新接口外，非 `no_auth` 模式下的业务请求必须携带统一认证头。
- 统一认证头字段为：`Authorization`、`x-downstream-session-id`、`x-downstream-token-id`、`x-token-type`、`x-downstream-principal`、`x-scopes`。
- `no_auth` 模式下，认证头可以为空或短路处理；`gateway` 不应在该模式下强制执行认证控制与限流控制。
- `edge_server` 的认证请求统一经 `gateway` 转发，不直接对接认证中心。

## 3. 业务接口

### 3.1 客户端业务接口

客户端业务接口均由 `gateway` 对外提供，业务数据最终由后端服务聚合返回。

| 接口 | 方法 | 请求 | 响应 | 说明 |
| --- | --- | --- | --- | --- |
| `/v1/client/users/register` | `POST` | `ClientRegisterRequest` | `ClientRegisterResponse` | 注册接口，唯一明确不携带统一认证头。 |
| `/v1/client/users/profile` | `GET` | `ClientUserProfileRequest`，`identifier` 作为查询条件 | `ClientUserProfileResponse` | 登录成功后拉取用户资料。 |
| `/v1/client/home/summary` | `GET` | `ClientHomeSnapshotRequest` | `ClientDashboardSnapshotResponse` | 首页概览聚合接口。 |
| `/v1/client/records/stations` | `GET` | `ClientRecordStationOptionsRequest` | `ClientRecordStationOptionResponse[]` | 记录页与统计页的站点选项。 |
| `/v1/client/records` | `GET` | `ClientRecordsCursorRequest` | `ClientRecordsCursorResponse` | 记录页游标分页接口。 |
| `/v1/client/stats/weekly-trend` | `GET` | `ClientWeeklyTrendRequest` | `ClientWeeklyTrendResponse` | 最近七日趋势接口。 |
| `/v1/client/stats/range-summary` | `GET` | `ClientRangeSummaryRequest` | `ClientRangeSummaryResponse` | 时间段统计接口。 |

客户端业务接口字段语义说明：

- `ClientRegisterRequest` 只承载账号注册所需的最小字段，不复用登录请求结构。
- `ClientRecordsCursorRequest` 的 `sort` 当前固定为 `captured_at_ms_desc`。
- `ClientRangeSummaryRequest` 的查询区间建议限制在 30 天内。
- `ClientAuthCredentialsResponse` 仅用于认证接口返回，不属于业务接口返回体。

### 3.2 边缘端业务接口

边缘端业务接口由 `edge_server` 通过 `gateway` 暴露，业务上传与认证恢复保持分离。

| 接口 | 方法 | 请求 | 响应 | 说明 |
| --- | --- | --- | --- | --- |
| `/v1/edge/events` | `POST` | 边缘事件上传 envelope | 上传 ACK / 结果对象 | 统一事件上传与补传入口，默认路径可配置。 |
| `/health` | `GET` | 空 | `200 OK` 或轻量健康文本 | 运维探活接口，不参与业务语义。 |

边缘端业务上传的请求体由事件编排器统一组装，通常包含采集元数据、推理结果、图像内容、设备标识、请求追踪字段等。`edge_server` 在非 `no_auth` 模式下必须为该业务请求附带统一认证头；在 `no_auth` 模式下认证字段可为空值。

## 4. 认证接口

### 4.1 客户端认证接口

| 接口 | 方法 | 请求 | 响应 | 说明 |
| --- | --- | --- | --- | --- |
| `/v1/client/auth/sign-in` | `POST` | `ClientSignInRequest` | `ClientAuthCredentialsResponse` | 客户端登录接口，`identifier` 可由用户名、邮箱或手机号承担。 |
| `/v1/client/auth/refresh-session` | `POST` | `ClientRefreshSessionRequest` | `ClientAuthCredentialsResponse` | 会话续期接口，输入来自本地持久化状态。 |

客户端认证请求的最小字段约定：

- `ClientSignInRequest`：`identifier`、`password`。
- `ClientRefreshSessionRequest`：`session_id`、`refresh_token`、`token_id`、`token_family_id`、`principal_id`、`scopes`。
- `ClientAuthCredentialsResponse`：`access_token`、`refresh_token`、`downstream_token`、`token_type`、`session_id`、`token_id`、`principal_id`、`token_family_id`、`scopes`、`issued_at_ms`、`access_expires_at_ms`、`refresh_expires_at_ms`、`persisted`。

### 4.2 边缘端认证接口

| 接口 | 方法 | 请求 | 响应 | 说明 |
| --- | --- | --- | --- | --- |
| `/v1/edge/auth/bootstrap/challenge` | `POST` | `device_id`、`key_id`、`audience` | `BootstrapChallenge` | 请求挑战，供边缘设备生成签名证明。 |
| `/v1/edge/auth/bootstrap/authenticate` | `POST` | `BootstrapChallenge` + `SignedBootstrapProof` | `EdgeAuthState` | 提交签名证明并换取会话与令牌。 |
| `/v1/edge/auth/token/refresh` | `POST` | `RefreshTokenRequest` | `EdgeTokenBundle` | 刷新长期凭证。 |
| `/v1/edge/auth/token/revoke` | `POST` | `token_id` / `family_id` | 保留 | 撤销令牌或令牌族；当前不开放。 |

边缘端认证接口的最小字段约定：

- `BootstrapChallenge`：`challenge_id`、`nonce`、`issuer`、`audience`、`issued_at`、`expires_at`、`entity_type`、`entity_id`、`key_id`。
- `SignedBootstrapProof`：`challenge_id`、`device_id`、`key_id`、`signature`、`signature_algorithm`、`signed_at`。
- `EdgeAuthState`：`stage`、`session`、`tokens`、`failure_reason`。
- `EdgeTokenBundle`：`access_token`、`refresh_token`。

与撤销凭证相关的语义接口当前统一标记为保留，不作为现行对外能力开放。

## 5. 关系说明

- 客户端与边缘端都只通过 `gateway` 访问后端能力。
- 客户端认证接口最终转发到 `certification_server` 的认证能力。
- 边缘端认证接口同样经由 `gateway` 转发到 `certification_server`。
- 客户端与边缘端的业务接口不应暴露内部 gRPC 方法，也不应直接绑定后端服务层函数。
- 网关业务转发的统一基线见 [`SYSTEM_GATEWAY_BUSINESS_FORWARDING_DESIGN.md`](SYSTEM_GATEWAY_BUSINESS_FORWARDING_DESIGN.md)。
