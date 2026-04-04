# Edge-Gateway 通信接口契约（认证通道 + 工作上传通道）

Version: 0.1.0
Status: Draft (用于后续自顶向下实现)

## 1. 目标与边界

本文档定义边缘端与网关之间的两条独立通信通道：

1. 认证通道：用于 bootstrap、token 刷新、校验、撤销。
2. 工作上传通道：用于业务事件上报与健康检查。

强约束：

- 两条通道在实现上必须隔离。
- 工作上传通道不承载认证流程编排。
- 认证通道不承载业务事件数据。

## 2. 通用约定

### 2.1 传输层

- 协议：HTTP/1.1 或 HTTP/2
- 编码：JSON (`application/json; charset=utf-8`)
- 字符集：UTF-8

### 2.2 时间字段

- 除特别说明外，时间戳使用 Unix 时间（秒，浮点）
- 业务捕拍时间 `captured_at_ms` 使用 Unix 时间（毫秒，整型）

### 2.3 通用请求头（建议）

- `X-Request-ID`：请求唯一 ID（建议 UUID）
- `X-Trace-ID`：链路追踪 ID（建议 UUID）
- `User-Agent`：边缘端版本信息

### 2.4 统一错误响应体

```json
{
  "code": "invalid_request",
  "message": "human readable message",
  "request_id": "optional-request-id",
  "trace_id": "optional-trace-id",
  "timestamp": "2026-04-03T10:00:00Z"
}
```

推荐错误码：

- `invalid_request`
- `unauthorized`
- `forbidden`
- `not_found`
- `rate_limited`
- `internal_error`

## 3. 认证通道接口（Edge <-> Gateway）

认证通道由边缘端的 `IEdgeGatewayAuthClient` 访问，网关负责转发到认证中心。

### 3.1 初始化 bootstrap challenge

- Method: `POST`
- Path: `/v1/edge/auth/bootstrap/challenge`

Request Body:

```json
{
  "device_id": "edge_device_001",
  "key_id": "edge-key-2026-01",
  "audience": "gateway"
}
```

字段说明：

- `device_id` (string, required)
- `key_id` (string, required)
- `audience` (string, optional, default: `gateway`)

Response Body (`BootstrapChallenge`):

```json
{
  "challenge_id": "a8f4d8c4-1c14-4d56-87e8-79b2d4fef1da",
  "nonce": "8f4be922-81ab-4b7c-87fd-bec7ac9f4e15",
  "issuer": "certification_server",
  "audience": "gateway",
  "issued_at": 1775191200.123,
  "expires_at": 1775191320.123,
  "entity_type": "device",
  "entity_id": "edge_device_001",
  "key_id": "edge-key-2026-01"
}
```

### 3.2 提交签名证明完成 bootstrap

- Method: `POST`
- Path: `/v1/edge/auth/bootstrap/authenticate`

Request Body (`SignedBootstrapProof`):

```json
{
  "challenge_id": "a8f4d8c4-1c14-4d56-87e8-79b2d4fef1da",
  "device_id": "edge_device_001",
  "key_id": "edge-key-2026-01",
  "signature": "base64-signature",
  "signature_algorithm": "ed25519",
  "signed_at": 1775191205.321
}
```

字段约束：

- `signature_algorithm` 仅允许：
  - `ed25519`
  - `ecdsa_p256_sha256`
  - `rsa_pss_sha256`

Response Body (`EdgeAuthState`):

```json
{
  "stage": "ready",
  "session": {
    "session_id": "2ec09a6f-c8ff-4722-8a6f-43bb3b69b30a",
    "principal_id": "device:edge_device_001",
    "device_id": "edge_device_001",
    "status": "active",
    "issued_at": 1775191205.4,
    "expires_at": 1775277605.4,
    "token_family_id": "0c8ff22d-6fdf-4650-bd9e-2ed57cefb2f4",
    "last_verified_at": 1775191205.4
  },
  "tokens": {
    "access_token": {
      "raw": "access.xxx",
      "token_type": "access",
      "token_id": "4f2f7e15-cf6a-4f1f-99f5-8bdfe41b28ec",
      "family_id": "0c8ff22d-6fdf-4650-bd9e-2ed57cefb2f4",
      "session_id": "2ec09a6f-c8ff-4722-8a6f-43bb3b69b30a",
      "issued_at": 1775191205.4,
      "expires_at": 1775191505.4,
      "scopes": ["edge:upload"],
      "role": "edge_device"
    },
    "refresh_token": {
      "raw": "refresh.xxx",
      "token_type": "refresh",
      "token_id": "e7034f8f-9f1f-459c-8e11-3d8a23249b0d",
      "family_id": "0c8ff22d-6fdf-4650-bd9e-2ed57cefb2f4",
      "session_id": "2ec09a6f-c8ff-4722-8a6f-43bb3b69b30a",
      "issued_at": 1775191205.4,
      "expires_at": 1775277605.4,
      "scopes": ["edge:upload"],
      "role": "edge_device"
    }
  },
  "failure_reason": ""
}
```

### 3.3 刷新 token

- Method: `POST`
- Path: `/v1/edge/auth/token/refresh`

Request Body (`RefreshTokenRequest`):

```json
{
  "refresh_token": "refresh.xxx",
  "client_id": "edge-server",
  "gateway_id": "gateway",
  "source_ip": "10.10.0.31",
  "user_agent": "edge-server-auth-transport",
  "request_id": "f09c35e9-1f2b-40a4-bcf4-b5d8a3be9d84",
  "trace_id": "f09c35e9-1f2b-40a4-bcf4-b5d8a3be9d84"
}
```

Response Body (`EdgeTokenBundle`):

```json
{
  "access_token": { "...": "same as 3.2 access_token" },
  "refresh_token": { "...": "same as 3.2 refresh_token" }
}
```

### 3.4 校验 token

- Method: `POST`
- Path: `/v1/edge/auth/token/verify`

Request Body:

```json
{
  "raw_token": "access.xxx",
  "expected_types": ["access"],
  "allow_expired_skew_sec": 0
}
```

Response Body (`TokenVerificationResult`):

```json
{
  "valid": true,
  "status": "active",
  "failure_reason": ""
}
```

### 3.5 撤销 token / family

- Method: `POST`
- Path: `/v1/edge/auth/token/revoke`

Request Body:

```json
{
  "token_id": "optional-token-id",
  "family_id": "optional-family-id"
}
```

约束：

- `token_id` 与 `family_id` 至少一个非空。

Response:

- `200 OK`（建议返回 `{ "status": "ok" }`）

### 3.6 认证状态字段枚举

- `stage`:
  - `uninitialized`
  - `challenge_issued`
  - `ready`
  - `refreshing`
  - `expired`
  - `revoked`
  - `failed`
- `session.status`:
  - `active`
  - `expired`
  - `revoked`
- `token.token_type`:
  - `access`
  - `refresh`

### 3.7 签名载荷规范

bootstrap 签名串必须严格使用以下拼接格式：

- `challenge_id|issuer|audience|entity_type|entity_id|key_id|nonce|issued_at_rfc3339nano|expires_at_rfc3339nano`

## 4. 工作上传通道接口（Edge Business Upload）

工作上传通道由 `IEdgeEventUploadCoordinator` 使用，主流程上传与补传共用同一 payload 结构。

### 4.1 上传事件

- Method: `POST`
- Path: `/v1/edge/events`

Request Headers:

- `Content-Type: application/json`
- `Authorization: Bearer <access_token>`
- `x-downstream-session: <session_id>`
- `x-downstream-token: <token_id>`
- `x-token-type: access`
- `x-downstream-principal: <principal_id>`
- `x-scopes: edge:upload,...` (optional)

> 说明：除 `Content-Type` 外，其余认证头由认证协调器输出（`EdgeAuthHeaders.to_http_headers`）。

Request Body:

```json
{
  "event_id": "f2d6bf6b-9527-4aa7-b3a5-e1d87d369f2f",
  "trace_id": "cf5de6d2-d959-4d40-a932-4a8fdf62ca56",
  "requires_server_assist": false,
  "context": {
    "device_id": "edge_device_001",
    "trigger_type": "motion",
    "sensor_snapshot": {"temperature": 24.5},
    "captured_at_ms": 1775193335123
  },
  "image": {
    "image_id": "img-001",
    "format": "jpg",
    "width": 1920,
    "height": 1080,
    "checksum_sha256": "optional-sha256"
  },
  "local_inference": {
    "success": true,
    "stage": "classified",
    "reason": "local_inference_confident",
    "crop_applied": true,
    "crop_box": {"x1": 0.12, "y1": 0.08, "x2": 0.51, "y2": 0.67},
    "detector_model_version": "det-v1",
    "classifier_model_version": "cls-v1",
    "detector_model_signature": "edge_yolo_n|yolo11n|onnx",
    "classifier_model_signature": "edge_mobilenet_cls|mobilenet_v3_large|custom",
    "detection": {
      "success": true,
      "reason": "",
      "latency_ms": 24,
      "model_signature": "edge_yolo_n|yolo11n|onnx",
      "boxes": [
        {"label": "bird", "confidence": 0.92, "x1": 0.11, "y1": 0.07, "x2": 0.52, "y2": 0.68}
      ]
    },
    "classification": {
      "success": true,
      "top1_label": "sparrow",
      "top1_confidence": 0.88,
      "latency_ms": 12,
      "reason": "",
      "model_signature": "edge_mobilenet_cls|mobilenet_v3_large|custom",
      "topk": [
        {"label": "sparrow", "confidence": 0.88},
        {"label": "finch", "confidence": 0.07}
      ]
    }
  },
  "metadata": {
    "decision_before_infer_reason": "normal_path",
    "decision_after_infer_reason": "local_inference_confident",
    "delivery_result": "upload_attempted"
  },
  "image_b64": "...base64 image bytes..."
}
```

字段规则：

- `event_id` (string, required)：幂等键，网关应据此做去重。
- `trace_id` (string, required)：跨链路追踪。
- `requires_server_assist` (bool, required)：边缘是否请求服务端辅助推理/判定。
- `context` (object, required)
- `image` (object, required)
- `local_inference` (object | null, optional)
- `metadata` (object, optional)
- `image_b64` (string, required)：原始图像 base64 编码。

### 4.2 上传成功响应

建议响应：

```json
{
  "status": "accepted",
  "event_id": "f2d6bf6b-9527-4aa7-b3a5-e1d87d369f2f",
  "ingest_id": "optional-ingest-id",
  "received_at_ms": 1775193336200
}
```

HTTP 状态建议：

- `200 OK`：同步处理成功
- `202 Accepted`：异步入队成功

### 4.3 上传失败响应

常见状态码建议：

- `400 Bad Request`：字段非法
- `401 Unauthorized`：token 无效
- `403 Forbidden`：权限不足
- `413 Payload Too Large`：payload 超限
- `429 Too Many Requests`：限流
- `5xx`：服务端错误

> 边缘端处理策略：上传失败即写入 spool，交由 `SyncWorker` 重试。

### 4.4 上传通道健康检查

- Method: `GET`
- Path: `/health`（或配置指定 `healthcheck_path`，由 `base_backend_url + healthcheck_path` 组合）

返回：

- `2xx` 视为通道可用
- 非 `2xx` 视为通道不可用

## 5. 两通道隔离与兼容策略

### 5.1 隔离要求

- 认证通道请求不可混入业务图像字段。
- 工作上传通道不可承载 challenge/signature/token 刷新参数。
- 业务模块仅依赖上传接口，不直接调用认证 API。

### 5.2 过渡兼容

- 工作上传通道认证头由 `EdgeAuthCoordinator.get_auth_headers()` 提供。

## 6. 与当前边缘端代码映射（用于后续实现）

- 认证接口入口：`src/iface/auth_interface.py`
- 认证状态模型：`src/models/auth/auth.py`, `src/models/auth/auth_contract.py`, `src/models/auth/bootstrap.py`
- 业务上传接口：`src/iface/upload_interface.py`
- 业务上传实现：`src/transport/event_uploader.py`
- 缓存与补传：`src/local_storage/sqlite_spool.py`, `src/sync_worker/sync_worker.py`

---

本契约作为后续实现唯一输入，若字段发生变更，需先更新本文件版本号并同步变更记录。
