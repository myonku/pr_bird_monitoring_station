# 后端认证 Proto 最小集冻结说明

状态：Frozen-Minimal
阶段：Bootstrap to Registry
适用模块：gateway / certification_server / data_worker

## 1. 冻结目标

本次冻结仅覆盖“后端模块 bootstrap 最小链路”所需 gRPC 契约，不覆盖完整认证系统。

冻结范围：

- 认证中心权威服务最小接口：challenge 初始化、bootstrap 认证。
- 启动链与注册链所需最小运行态元数据表达。
- 跨语言统一字段语义（Go/Python）。

非冻结范围：

- token verify / session validate / refresh / revoke。
- downstream grant 与 target_reverify。
- commsec 握手与加解密 RPC。
- 服务发现注册本身（当前仍由 etcd 客户端直接处理，不走 gRPC）。

## 2. 冻结结论

### 2.1 Proto 文件与包名

- 文件：schemas/proto/auth/v1/auth_authority_bootstrap.proto
- package：bms.auth.v1
- go_package：pr_bird_monitoring_station/schemas/proto/auth/v1;authv1

### 2.2 时间与 ID 规范

- UUID 统一使用 string（文本 UUID v4）。
- 时间统一使用 int64 的 epoch milliseconds（*_ms 字段后缀）。
- 可空对象使用 message 可省略字段表达，不引入额外 wrapper。

### 2.3 最小服务

服务名：AuthAuthorityBootstrapService

- InitBootstrapChallenge
- AuthenticateBootstrap

两条方法可满足：

- gateway / data_worker 在本地完成 challenge 签名后向认证中心提交 bootstrap。
- 认证中心返回最小可持久化凭证快照所需字段，支撑后续“注册到服务发现”链路。

## 3. 方法语义冻结

### 3.1 InitBootstrapChallenge

请求：BootstrapChallengeRequest

- 声明调用方实体信息（entity_type/entity_id/key_id）。
- 传递请求上下文（request_id/trace_id/client_id/gateway_id/source_ip/user_agent）。
- 允许携带最小运行态标识 runtime。

响应：BootstrapChallengeResponse

- 返回 challenge payload（包含 challenge_id、nonce、过期时间）。

### 3.2 AuthenticateBootstrap

请求：BootstrapAuthenticateRequest

- 包含 challenge payload 原文。
- 包含签名证明 signed。
- 包含 scopes/role 与 require_downstream_token。

响应：BootstrapAuthenticateResponse

- stage（bootstrap 阶段）。
- identity / session / tokens 最小快照。
- active_comm_key_id 与 issued/expires 时间。

## 4. 字段冻结说明

### 4.1 EntityType

- ENTITY_TYPE_USER
- ENTITY_TYPE_DEVICE
- ENTITY_TYPE_SERVICE

### 4.2 SignatureAlgorithm

- SIGNATURE_ALGORITHM_ECDSA_P256_SHA256
- SIGNATURE_ALGORITHM_ED25519
- SIGNATURE_ALGORITHM_RSA_PSS_SHA256

### 4.3 BootstrapStage

- BOOTSTRAP_STAGE_UNINITIALIZED
- BOOTSTRAP_STAGE_CHALLENGING
- BOOTSTRAP_STAGE_AUTHENTICATING
- BOOTSTRAP_STAGE_READY

### 4.4 TokenType（最小）

- TOKEN_TYPE_ACCESS
- TOKEN_TYPE_REFRESH
- TOKEN_TYPE_DOWNSTREAM

### 4.5 ServiceInstanceMetadata（冻结结构，仅作统一元数据表达）

说明：

- 当前服务发现仍由 etcd 注册服务直接处理。
- 该消息用于冻结跨模块一致的实例元数据形状，供后续扩展 RPC 或审计事件复用。

字段：

- id
- service_id
- name
- endpoint
- heartbeat_ms
- zone
- version
- weight
- tags
- active_comm_key_id
- metadata

## 5. 路由映射配套约定（与 proto 冻结同步）

本阶段对 proto 对应方法固定 route_key：

- InitBootstrapChallenge -> auth.bootstrap.challenge
- AuthenticateBootstrap -> auth.bootstrap.authenticate

固定 flow_category：bootstrap_call。

安全策略：

- 当前阶段允许以最小链路联通为优先，不强制绑定 commsec 通道。
- 进入下一阶段时再收敛为 required 或按链路类型分级。

## 6. 版本与兼容策略

- v1 阶段仅允许“向后兼容”的字段追加。
- 已发布字段号禁止复用。
- 删除字段必须使用 reserved 保留字段号与名称。
- 发生破坏性变更时升级到 bms.auth.v2。

## 7. 生成与落地建议

- Go：由 gateway/certification_server 共用同一生成产物。
- Python：data_worker 使用同一 proto 生成客户端桩。
- 代码接入时，先完成适配层转换，不直接把 proto message 透传到领域模型。

## 8. 本阶段验收标准

- 三模块对 bootstrap RPC 的请求/响应字段含义一致。
- 认证中心可作为唯一权威服务定义源。
- 不实现 verify/refresh/revoke 也不影响本阶段“启动链到注册”推进。
- 后续实现不会因为字段歧义而返工接口命名或 ID/时间格式。
