# 边缘端认证模块设计说明

## 1. 目标

本文档定义鸟类监测平台边缘端认证模块的架构设计。

范围：
- 边缘认证模块的分层与接口边界。
- 认证模型与传输适配层之间的数据契约映射。
- 认证通道与业务上传通道的隔离约束。

不在范围内：
- 跨模块认证链路与启动链路的全局定义。
- 全局标识/密钥/配置生命周期规范。
- 业务 payload 结构与上传编排细节。
- 边缘端与网关之间的传输层加密细节。


## 2. 约束与假设

1. 边缘运行时不直接连接远端数据库。
2. 边缘端不直接调用认证中心，认证请求统一经网关转发。
3. 认证通道与业务上传通道必须严格隔离。
4. 全局标识、密钥与配置生命周期规则见 `SYSTEM_GLOBAL_BASELINE_DESIGN.md`。
5. 认证接口 HTTP 契约统一见 `SYSTEM_EXTERNAL_INTERFACE_CATALOG_DESIGN.md`，实现以本模块代码与全局基线约束为准。
6. 边缘端认证模块不承担 commsec/EnsureChannel 握手编排；在 `full_development` 模式下本分区不要求 TLS 配置。
7. 运行模式约束：
	- development：认证模块不初始化，仅保留业务本地流程；
	- no_auth：认证模块初始化为占位实现，不执行 bootstrap/refresh/鉴权恢复；对业务流程暴露的认证字段全部为空值；
	- full_development：启动前必须确保长期凭证可用（refresh token）；若缺失则先 bootstrap，失败则拒绝启动。
8. `auth.active_key_id` 可为空：challenge 初始化阶段允许后端按 `runtime.device_id` 回查当前生效公钥；边缘端本地需能解析对应私钥完成签名。


## 3. 分层与隔离

认证能力必须独立于业务流程（采集/推理/上传）。

边界约束：
- 业务模块仅依赖认证头提供能力。
- 业务模块不构建 bootstrap 请求、不执行 challenge 签名、不直接处理 refresh。
- 业务模块不解析认证响应细节。

建议依赖方向：
- business pipeline -> IEdgeAuthCoordinator
- IEdgeAuthCoordinator -> ISecretKeyManager, IEdgeGatewayAuthClient, IEdgeAuthStateStore
- 认证组件不得依赖业务 pipeline 模块


## 4. 接口集合

对应实现位置：
- src/iface/auth_interface.py
- src/models/auth/auth.py
- src/models/auth/auth_contract.py
- src/models/auth/bootstrap.py
- src/transport/auth_transport.py
- src/utils/crypto_utils.py
- src/utils/secret_key_utils.py

核心抽象：
1. ISecretKeyManager
- 提供本地信任材料、密钥检索与 PEM 装载能力；签名算法识别与签名流程由 CryptoUtils 与认证编排层负责。

2. IEdgeGatewayAuthClient
- 调用网关认证 API：
- init bootstrap challenge
- authenticate bootstrap
- refresh token
- revoke token/family（保留，不作为当前实现能力）

3. IEdgeAuthStateStore
- 本地持久化认证状态（session + token bundle + stage）。
- 建议存储实现：文件、sqlite、轻量 kv。

4. IEdgeAuthCoordinator
- 面向业务模块的认证编排入口。
- 对外能力：
- ensure_ready
- ensure_startup_ready
- get_auth_headers
- on_unauthorized
- logout
- 约束：ensure_ready 仅覆盖“边缘端自身认证可用”检查（session/token 可用），不承担网关与内部服务通道建立职责。
- 约束：ensure_startup_ready 作为 full_development 启动门禁，至少保证长期凭证可用；长期凭证不可用时必须先 bootstrap。


## 5. 数据契约

关键契约位于 src/models/auth/auth.py、src/models/auth/auth_contract.py、src/models/auth/bootstrap.py：
- LocalTrustMaterial
- BootstrapChallenge
- SignedBootstrapProof
- EdgeToken / EdgeTokenBundle
- EdgeSession
- EdgeAuthState
- RefreshTokenRequest
- TokenVerificationResult
- EdgeAuthHeaders

设计说明：
- 模型字段尽量保持协议中立。
- 与网关 HTTP payload 的具体映射放在 adapter/client 层。

### 5.1 Bootstrap 签名载荷规范格式

边缘端签名载荷必须与认证中心验签器期望完全一致：

- challenge_id|issuer|audience|entity_type|entity_id|key_id|nonce|issued_at_rfc3339nano|expires_at_rfc3339nano

对应实现位于 src/utils/crypto_utils.py：
- CryptoUtils.build_bootstrap_signature_payload
- CryptoUtils.unix_ts_to_rfc3339nano
- CryptoUtils.detect_signature_algorithm_from_private_key
- CryptoUtils.detect_signature_algorithm_from_public_key

密钥加载与本地 key catalog 查询位于 src/utils/secret_key_utils.py：
- SecretKeyUtils.load_pem_bytes_from_ref
- SecretKeyUtils.get_local_trust_material
- SecretKeyUtils.get_private_key_pem
- SecretKeyUtils.get_public_key_pem

支持的签名算法：
- ed25519
- ecdsa_p256_sha256
- rsa_pss_sha256


## 6. 全局引用

- 跨模块认证链路与启动链路见 `SYSTEM_AUTH_STARTUP_CHAIN_DESIGN.md`。
- 全局统一约定见 `SYSTEM_GLOBAL_BASELINE_DESIGN.md`。
- 边缘端到网关的外部接口清单见 `SYSTEM_EXTERNAL_INTERFACE_CATALOG_DESIGN.md`；本文档仅承载边缘认证模块内部架构定义。
- 本文档仅承载边缘认证模块内部架构定义。
- 边缘端上传链路在 `full_development` 模式下不强制要求 TLS 配置，不引入 commsec 握手流程。
