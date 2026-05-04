# Edge Server Bootstrap 认证测试报告

## 测试概述

已成功在full_development模式下测试edge_server通过网关向认证中心提交的bootstrap和token refresh认证请求。

## 测试环境

- **认证中心**: certification_server (gRPC 127.0.0.1:50051)
- **网关**: gateway (HTTP 127.0.0.1:8080)
- **Edge设备**: 伪造请求
  - Device ID: `6a9d6b92-fe06-44ee-a607-7284e783f738`
  - Key ID: `626efa4f-0cd0-4e81-af6e-447b41bac8fc`
  - Signature Algorithm: RSA-PSS-SHA256

## 测试流程

### [PASS] 1. Bootstrap Challenge 请求

```
POST /v1/edge/auth/bootstrap/challenge HTTP/1.1
Content-Type: application/json

{
  "device_id": "6a9d6b92-fe06-44ee-a607-7284e783f738",
  "key_id": "626efa4f-0cd0-4e81-af6e-447b41bac8fc",
  "audience": "gateway"
}
```

**响应**:
- Challenge ID: `625403a4-a9b6-4b04-b44d-67ddbde7885f`
- Nonce: `04887c71-bc5d-4b8b-974d-cb98c3ec4806`
- Issuer: `certification_server`
- Issued At (ms): `1777858763377`
- Expires At (ms): `1777858823377` (TTL: 60 秒)

### [PASS] 2. Bootstrap Authenticate (Signature Verification)

请求格式（正确格式）:
```
POST /v1/edge/auth/bootstrap/authenticate HTTP/1.1
Content-Type: application/json

{
  "challenge": {
    "challenge_id": "625403a4-a9b6-4b04-b44d-67ddbde7885f",
    "nonce": "04887c71-bc5d-4b8b-974d-cb98c3ec4806",
    "issuer": "certification_server",
    "audience": "gateway",
    "issued_at_ms": 1777858763377,
    "expires_at_ms": 1777858823377,
    "entity_type": "device",
    "entity_id": "6a9d6b92-fe06-44ee-a607-7284e783f738",
    "key_id": "626efa4f-0cd0-4e81-af6e-447b41bac8fc"
  },
  "signed": {
    "challenge_id": "625403a4-a9b6-4b04-b44d-67ddbde7885f",
    "device_id": "6a9d6b92-fe06-44ee-a607-7284e783f738",
    "key_id": "626efa4f-0cd0-4e81-af6e-447b41bac8fc",
    "signature": "gi28WwmzHa+uToZ+KO5ewUC7BIq2j8fxidBu74vPCDrYcAE9eC...",
    "signature_algorithm": "rsa_pss_sha256",
    "signed_at_ms": 1777858763500
  },
  "scopes": [],
  "role": "device",
  "require_downstream_token": false
}
```

**关键发现**:
1. ✓ 签名载荷格式正确：`challenge_id|issuer|audience|entity_type|entity_id|key_id|nonce|issued_at_rfc3339nano|expires_at_rfc3339nano`
2. ✓ 时间戳精度修复已生效（毫秒→RFC3339Nano格式正确）
3. ✓ 网关期望的是完整的Challenge对象+SignedProof，不是flatten格式
4. ✓ 时间戳需要从毫秒转换（gateway返回`*_ms`字段）

**响应**:
```json
{
  "stage": "ready",
  "session": {
    "session_id": "fc93892c-f108-45a7-ba39-881dbbbfbfd5",
    "status": "active",
    "issued_at": 1777858763.5,
    "expires_at": 1777858923.5
  },
  "tokens": {
    "access_token": {
      "token_id": "8c62a132-1011-4ce9-b9f1-480ef82ce80a",
      "token_type": "access",
      "issued_at": 1777858763.5,
      "expires_at": 1777858923.5,
      "scopes": ["service:bootstrap"]
    },
    "refresh_token": {
      "token_id": "8c62a132-1011-4ce9-b9f1-480ef82ce80a",
      "token_type": "refresh",
      "issued_at": 1777858763.5,
      "expires_at": 1777858923.5
    }
  }
}
```

### [PASS] 3. Token Refresh

```
POST /v1/edge/auth/token/refresh HTTP/1.1
Content-Type: application/json

{
  "refresh_token": "...",
  "client_id": "edge-server-test",
  "gateway_id": "gateway",
  "source_ip": "127.0.0.1",
  "user_agent": "edge-server-test",
  "request_id": "...",
  "trace_id": "..."
}
```

**结果**: ✓ 成功获取新的access/refresh tokens

## 关键发现与修复

### 问题1: 时间戳精度（已在bootstrap_time_precision_fix中修复）

**症状**: Bootstrap签名验证失败，错误"challenge response mismatch"

**原因**: 
- certification_server使用`time.Now().UTC().Truncate(time.Millisecond)`创建毫秒精度challenge
- Proto使用`UnixMilli()`序列化为毫秒整数
- Edge接收后转回float秒数：IEEE 754浮点精度丢失（如1777858763.377实际为1777858763.376999...）
- 旧算法`(ts - sec) * 1e9`计算错误纳秒值，导致RFC3339Nano格式不匹配

**解决**: 采用毫秒恢复算法
```python
ms = round(ts * 1000.0)
sec = ms // 1000
nanos = (ms % 1000) * 1_000_000
```

**验证**: ✓ 修复后edge_server正确生成RFC3339Nano格式，通过认证中心验签

### 问题2: Gateway Bootstrap API合约理解

**发现**:
- 初期误认为bootstrap/authenticate期望flat格式：`{challenge_id, device_id, key_id, signature, ...}`
- 实际期望嵌套格式：`{challenge: {...}, signed: {...}}`
- 时间戳需转换：gateway返回`issued_at_ms/expires_at_ms`（毫秒）, 需转换为秒供edge_server处理

**修正**: ✓ 测试脚本已按网关实际API合约调整

## 完整认证流程验证

1. ✓ Device→Gateway: Bootstrap challenge request
2. ✓ Gateway→Certification_server: Challenge creation (gRPC)
3. ✓ Gateway→Device: Challenge response (毫秒时间戳)
4. ✓ Device: 生成signed proof (RFC3339Nano格式，时间精度正确)
5. ✓ Device→Gateway: Bootstrap authenticate request
6. ✓ Gateway→Certification_server: Proof verification (gRPC)
7. ✓ Gateway→Device: Session + token response
8. ✓ Device→Gateway: Token refresh request
9. ✓ Gateway→Certification_server: Token refresh (gRPC)
10. ✓ Gateway→Device: New token response

## 测试文件

1. **test_bootstrap_auth_flow.py** - 完整的edge_server bootstrap和refresh认证测试
2. **debug_bootstrap.py** - 单步调试脚本，用于问题排查

## 运行测试

```bash
cd edge_server
.\.venv\Scripts\python.exe tests/test_bootstrap_auth_flow.py
```

## 结论

✓ **PASSED** - Edge server在full_development模式下通过网关进行的bootstrap和token refresh认证流程完全正常工作。时间戳精度修复已验证有效。
