# Certification Server 设计说明（完成版）

版本：2.0.0
状态：Completed
日期：2026-04-16

## 1. 模块定位

certification_server 是认证中心与权威凭证服务端，唯一入站协议是 gRPC。它负责 bootstrap、远程令牌校验、会话校验、用户名密码认证、token refresh，以及与这些流程相关的本地密钥、会话、令牌、注册信息维护。

该模块不承担网关式转发职责，不承担外部 HTTP 入口职责，也不再保留独立的通道管理能力。非网关场景下的 AuthControl 只做本地入站限流和规则消费，不调用其他服务。

## 2. 运行时层级

认证中心当前实际运行层级如下：

1. Inbound Adapter：`src/services/communication/rpc_service/*`
2. Traffic Station：`src/services/communication/traffic_station_svc.go`
3. Routing / Payload Pipeline：`src/services/communication/routing_payload_pipeline_svc.go`
4. AuthControl：`src/services/authcontrol/inbound_auth_control_svc.go`
5. Auth Request Orchestrator：`src/services/orchestration/*`
6. Capability Modules：`SecretKeyService`、`UserCredentialService`、`SessionService`、`TokenService`
7. Data Managers：`RegistryService`
8. Storage：MySQL、Redis、Etcd、filesystem

这些层之间是单向调用关系。RPC Handler 不直接访问 repo，也不绕过 Traffic Station 直连编排层。

## 3. 启动顺序

认证中心启动的真实顺序如下：

1. `LoadConfig` 读取 `settings.toml` 或 `CERTIFICATION_SETTINGS_PATH`。
2. `ProjectConfig.Normalized` 归一化 `runtime`、`auth`、`auth_control`。
3. 如果 `runtime.run_mode == no_auth`，进程在进入依赖初始化前直接退出，不启动 MySQL、Redis、Etcd 或 gRPC server。
4. 若进入正常模式，按配置选择性初始化 MySQL、Redis、Etcd 客户端。
5. 构建 `RegistryService`。
6. 构建 `SecretKeyService`，并将 `active_key_id` 优先、`instance_id` 回退后的启动参数传入。
7. 构建 `SessionService`、`TokenService`、`UserCredentialService`。
8. 构建 `RoutingPayloadPipelineService`、`InboundAuthControlService`、`TrafficStationService`。
9. 构建 `AuthRequestOrchestratorService`。
10. 注册 `bootstrap`、`remote_auth`、`external_auth`、`token_refresh` 四类 gRPC 服务。
11. 启动 gRPC server，并在退出时清理 registry。

## 4. 配置分区

当前认证中心配置分为以下 section：

| Section | 作用 |
| --- | --- |
| `runtime` | 服务标识、实例标识、运行模式、gRPC 监听地址 |
| `mysql` | MySQL 连接串、连接池、超时和熔断配置 |
| `redis` | Redis 运行模式、地址、池、超时、TTL 和熔断配置 |
| `etcd` | 服务注册、发现和锁相关连接配置 |
| `auth` | 本地密钥目录和 active key 引用 |
| `auth_control` | 非网关本地入站限流与规则匹配配置 |

配置加载只在启动期执行一次，运行期使用快照值。

## 5. 实际调用流程

### 5.1 Bootstrap 流程

`AuthAuthorityBootstrapRPCService` 的 `InitBootstrapChallenge` 和 `AuthenticateBootstrap` 都先进入 `BootstrapFlowHandler`，再走统一入站控制：

1. gRPC handler 组装 `RoutingInput` 和请求头。
2. `BootstrapFlowHandler` 调用 `TrafficStation.HandleInbound`。
3. `TrafficStationService` 调用 `RoutingPayloadPipeline.BuildInboundPolicy`。
4. `RoutingPayloadPipelineService` 识别 `bootstrap.challenge` 或 `bootstrap.authenticate` 的路由类别。
5. `TrafficStationService` 将本次入站上下文转成 `InboundRateLimitInput`，调用 `AuthControl.EnforceInbound`。
6. `InboundAuthControlService` 构建 `RateLimitDescriptor`，按本地规则和进程内窗口做限流决策。
7. 如果放行，`BootstrapFlowHandler` 将 proto 请求转换为领域请求。
8. `TrafficStationService` 将 `flow_category`、`security_policy`、`operation`、`target_service_type`、`target_service_name`、`target_endpoint` 和 `rate_limit_*` 结果写回 `TrafficDecision.Metadata`。
9. `AuthRequestOrchestratorService.HandleBootstrapChallenge` 生成 challenge。
10. `AuthRequestOrchestratorService.HandleBootstrapAuthenticate` 先通过 `KeyManager` 读取公钥并验签，再调用 `SessionService`、`TokenService` 完成凭证签发。
11. gRPC handler 将领域结果转换回 proto 响应。

关键调用点：

- Challenge 生成使用 `HandleBootstrapChallenge`。
- Challenge 验签使用 `verifyBootstrapChallengeSignature`。
- 会话签发使用 `SessionService.CreateSession`。
- 令牌签发使用 `TokenService.IssueTokenBundle`，必要时再补发 downstream token。

### 5.2 Remote Auth 流程

`AuthAuthorityRemoteAuthRPCService` 负责 `VerifyToken` 和 `ValidateSession`：

1. gRPC handler 组装 `RoutingInput`。
2. `TrafficStation.HandleInbound` 先过路由分类与本地 AuthControl。
3. 路由分类命中 `auth.remote.verify.token` 或 `auth.remote.validate.session`。
4. 放行后进入 `AuthRequestOrchestratorService`。
5. `HandleTokenVerify` 调用 `TokenService.VerifyToken`。
6. `HandleSessionValidate` 调用 `SessionService.ValidateSession`。
7. 结果映射回 proto。

### 5.3 External Auth 流程

`AuthAuthorityExternalAuthRPCService` 负责用户密码认证、token refresh，以及对外部 bootstrap 的代理入口：

1. `ForwardUserPassword` 先构造 `RoutingInput` 和 header。
2. `TrafficStation.HandleInbound` 经过 `RoutingPayloadPipeline` 和 `AuthControl`。
3. 通过后，`HandleUserPasswordAuth` 调用 `UserCredentialService.ValidateCredentials`。
4. `UserCredentialService` 读取 MySQL 的 `entitiy_users`，校验用户状态和密码哈希。
5. 编排层再调用 `SessionService.CreateSession` 和 `TokenService.IssueTokenBundle`。
6. `ForwardRefreshTokenBundle` 经过相同的入口链，最终调用 `HandleTokenRefresh`。
7. 外部 bootstrap 代理入口 `ForwardBootstrapChallenge`、`ForwardBootstrapAuthenticate` 复用 `BootstrapFlowHandler`，只是入口路由不同。

### 5.4 Token Refresh 流程

`AuthAuthorityTokenRefreshRPCService.RefreshTokenBundle` 走模块刷新通路：

1. gRPC handler 生成 `RoutingInput`，route key 为 `auth.module.refresh.token_bundle`。
2. `TrafficStationService` 先做规则匹配和本地限流。
3. 放行后，`AuthRequestOrchestratorService.HandleTokenRefresh` 调用 `TokenService.RefreshTokenBundle`。
4. 结果映射回 proto token bundle。

## 6. 路由与调用映射

| RPC 方法 | route key | flow category | 主要下游 |
| --- | --- | --- | --- |
| `InitBootstrapChallenge` | `auth.bootstrap.challenge` | `bootstrap_call` | `HandleBootstrapChallenge` -> `SecretKeyService` |
| `AuthenticateBootstrap` | `auth.bootstrap.authenticate` | `bootstrap_call` | `HandleBootstrapAuthenticate` -> `SecretKeyService` / `SessionService` / `TokenService` |
| `VerifyToken` | `auth.remote.verify.token` | `remote_auth_verify` | `HandleTokenVerify` -> `TokenService` |
| `ValidateSession` | `auth.remote.validate.session` | `remote_auth_verify` | `HandleSessionValidate` -> `SessionService` |
| `ForwardUserPassword` | `auth.external.forward.user_password` | `external_auth_forward` | `HandleUserPasswordAuth` -> `UserCredentialService` / `SessionService` / `TokenService` |
| `ForwardRefreshTokenBundle` | `auth.external.forward.token_refresh_bundle` | `external_auth_forward` | `HandleTokenRefresh` -> `TokenService` |
| `ForwardBootstrapChallenge` | `auth.external.forward.bootstrap.challenge` | `external_auth_forward` | `BootstrapFlowHandler` |
| `ForwardBootstrapAuthenticate` | `auth.external.forward.bootstrap.authenticate` | `external_auth_forward` | `BootstrapFlowHandler` |
| `RefreshTokenBundle` | `auth.module.refresh.token_bundle` | `module_token_refresh` | `HandleTokenRefresh` -> `TokenService` |

`RoutingPayloadPipelineService` 以 route key 和 gRPC path 两条线共同识别流量类别，但真正的可信判断由 route key / method / path 归一化后的 `RouteProfile` 和 `InboundPolicyPlan` 决定。

## 7. 功能模块职责

### 7.1 AuthControl

`InboundAuthControlService` 只做本地入站限流和规则匹配，不调用外部服务。它接受来自 Traffic Station 的标准化输入，构建 `RateLimitDescriptor` 后，根据 `AuthControlConfig` 做固定窗口或 token bucket 决策。

### 7.2 SecretKeyService

`SecretKeyService` 负责本地单活密钥对和公钥目录查询。它读取固定的 `public.pem` / `private.pem`，并提供 `LookupPublicKey`、`GetPublicKey`、`GetPrivateKeyRef` 等能力，供 bootstrap 验签和服务内签名使用。

### 7.3 UserCredentialService

`UserCredentialService` 只做凭证验证，不做人身管理：

1. 从 MySQL 查询 `entitiy_users`。
2. 按 `username`、`email`、`phone` 依次检索。
3. 检查用户状态和风控标记。
4. 用 `CryptoUtils.VerifyPasswordHash` 校验密码。
5. 返回最小身份快照给编排层。

### 7.4 SessionService

`SessionService` 负责会话创建、校验、触达和撤销，当前以 Redis + 内存回退为主。

### 7.5 TokenService

`TokenService` 负责 access / refresh / downstream token 的签发、刷新、验证和撤销，支持 family 级操作。

### 7.6 RegistryService

`RegistryService` 负责 Etcd 注册与发现，供认证中心实例注册自身地址和活性信息。

## 8. no_auth 行为

当前认证中心在 `no_auth` 模式下的行为是：读取并归一化配置后立即自停止，不进入依赖初始化，也不打开 gRPC server。这意味着 `settings.toml` 中即使包含 mysql、redis、etcd 示例项，也只作为配置样例保留，不影响最小测试模式的退出行为。

## 9. 失败与拒绝规则

1. 请求为空或路由为空，直接返回参数错误。
2. 路由无法识别，直接返回 `RouteProfileNotFound`。
3. AuthControl 命中拒绝，Traffic Station 直接返回拒绝原因，gRPC 层映射为权限拒绝。
4. bootstrap challenge 缺失或签名不匹配，返回 challenge 相关错误。
5. MySQL / Redis / Etcd 未配置时，相应能力模块在运行期按依赖缺失处理。
6. gRPC handler 不允许直接访问 repo 或绕开 Traffic Station。

## 10. 已完成边界

以下内容在当前版本中已完成并视为稳定边界：

- bootstrap、remote_auth、external_auth、token_refresh 四类 gRPC 能力已接入主流程。
- 非网关 AuthControl 已接入 Traffic Station，并作为本地限流门面工作。
- 配置文件已收敛为 `runtime`、`mysql`、`redis`、`etcd`、`auth`、`auth_control`。
- 启动链已支持 no_auth 自停止。

## 11. 参考

- SYSTEM_BACKEND_LAYER_REFACTOR_DRAFT.md
- SYSTEM_GLOBAL_BASELINE_DESIGN.md
- SYSTEM_AUTH_STARTUP_CHAIN_DESIGN.md
- SYSTEM_NO_AUTH_STARTUP_CHAIN_DESIGN.md
