# 后端服务层级结构重构草案（V1 收敛）

版本：0.8.1
状态：Draft
日期：2026-04-13

---

## 1. 目的与范围

本草案用于在现有全局约束不变的前提下，定义一版可落地的后端层级结构，重点解决以下问题：

- 统一所有服务模块的流量站点入口。
- 将流量分路下沉到通信层下层处理。
- 抽离通道安全设计，收敛路由分路与载荷处理边界。
- 修正 AuthControl 与凭证管理模块语义边界。
- 明确网关认证转发与业务转发的双端校验流程。
- 明确底层数据管理模块分类，便于上层调用关系梳理与后续重构拆分。

本草案适用模块：

- gateway
- certification_server
- data_worker
- 普通服务模板（若后续恢复 api_service，可直接套用）

本草案不直接覆盖：

- edge_server（边缘侧链路另有独立文档）
- model_trainer（非运行期后端服务链路）

继承约束来源：

- SYSTEM_GLOBAL_BASELINE_DESIGN.md
- SYSTEM_AUTH_STARTUP_CHAIN_DESIGN.md
- SYSTEM_NO_AUTH_STARTUP_CHAIN_DESIGN.md

---

## 2. 需求整理（修正版）

结合当前主线，整理为以下七条硬约束与三条实施原则。

### 2.1 硬约束

1. 统一流量站点

- 每个后端模块必须对入站/出站流量保留明确的流量边界与协同语义。
- 远程认证调用、认证请求转发、普通业务转发需要遵守统一路由与策略语义，但不强制落在同一个实现层级或同一个编排模块。
- 载荷是否加密不影响站点入口语义。

2. 分路下沉到通信层下层

- 通信层下层根据路由映射完成流量分类。
- gateway 在此处获取目标服务类型（例如认证中心/普通服务）。
- 不再在顶层通信抽象上按 auth/business 进行通道切分。

3. 载荷处理独立化

- 载荷处理模块只负责载荷准备、转换与投递，不承担连接生命周期或额外安全准备编排。
- 不承担路由分类、认证策略决策、业务编排。

4. 认证控制语义修正

- AuthControl 不再承担凭证状态管理。
- Gateway 的 AuthControl 是全局统一认证校验与限流控制点，负责远程认证调用（到认证中心）并基于结果执行限流。
- 认证中心外其他服务模块（例如 data_worker、普通服务）的 AuthControl 仅做本地资源级限流，不做远程认证调用。
- AuthControl 不调用 bootstrap，不承担载荷处理或通道管理职责。

5. 凭证状态管理独立化

- 非认证中心模块新增独立 LocalCredentialManager 模块承接本地凭证状态管理。
- Bootstrap 流程获取凭证后，必须写入 Redis 缓存且写入成功才视为流程成功。
- 若 Redis 写入失败，必须向上层编排返回错误并通知上层决策（重试、降级或拒绝）。
- LocalCredentialManager 负责本模块凭证读取、续期状态更新、失效与回收。
- 认证中心的全局凭证状态管理由 SessionManager + TokenManager 承担。

6. 网关认证转发与业务转发补全

- 网关需要具备外部 bootstrap/密钥校验请求转发到认证中心的初始认证转发能力。
- 网关向内部服务转发业务流量时，当前仅保留基础转发链，不再申请下游授权。
- 目标服务保留本地 AuthControl 与业务处理，不再保留独立二次校验链路。
- 下游授权与目标侧复核方案已裁撤，不作为本阶段设计目标。

7. 协议与通信角色显式固定

- gateway 对外统一接收 HTTP 请求，必须持有 HTTP server。
- gateway 对内统一使用 gRPC client 发起转发与认证相关调用。
- certification_server 作为认证权威入口，显式持有 gRPC server。
- 其他内部模块间通信统一使用 gRPC：普通模块必须同时具备 gRPC server 与 gRPC client。
- 内部模块之间不引入 HTTP 作为服务间协议。
- 以上协议角色必须在详细结构设计中显式标注到模块层级与适配器分配。

### 2.2 实施原则

1. 减少横向调用

- 能力模块之间避免直接互调。
- 优先由上层编排模块做行为决策与调用顺序控制。

2. 上层决策优先

- 认证恢复、重试策略、降级策略由上层统一决策。
- 能力模块只提供单一能力，不隐式触发其他能力链。

3. no-auth 测试模式硬约束

- no-auth 模式禁用全部认证系统与额外安全准备，仅保留基础业务能力用于测试。
- no-auth 模式下认证中心默认被屏蔽（或不启动）。

---

## 3. 全局层级模型（目标形态）

### 3.1 逻辑分层

L1 入口适配层（Transport Adapters）

- HTTP/gRPC/任务消费入口。
- 只做协议转换与上下文标准化。

说明：本草案中的 Traffic Station 仅表示统一的路由与策略协同语义，不要求所有模块的入站与出站都复用同一个具体实现类；模块可以按职责拆分出独立的入站适配、出站适配或编排层，只要对外表现保持一致。

L2 统一流量站点层（Traffic Station）

- 对内提供统一的入站/出站流量调用面。
- 所有调用都先进入此层。

L3 通信下层（Routing + Payload Pipeline）

- 基于路由映射计算目标服务类型与流量分类。
- 依据策略决定是否执行载荷处理步骤。
- 调用独立的载荷处理能力，不实现通道状态本体。

L4 流程编排层（Usecase / Orchestration）

- 决定何时调用认证控制、何时触发 bootstrap、何时调用载荷处理。
- 承担重试、失败恢复、模式分支（auth/no-auth）。

L5 能力模块层（Capability Modules）

- AuthControl（含 RateLimit）：认证结果消费与限流决策。
- Bootstrap：凭证初始化/恢复流程。
- LocalCredentialManager：非认证中心模块的凭证缓存与状态管理（Redis 为主）。
- PayloadPipeline：载荷组装、头部整理与投递适配。
- RouteMapping：路由规则与目标选择。
- DataManagers：Registry/Session/Token/Key/ServiceResolver/PolicySnapshot/LocalCredential 等面向数据状态的管理模块。

L6 基础设施层（Repo / SDK / Runtime）

- 存储、服务发现、网络客户端、缓存等。

### 3.2 依赖方向

- L1 -> L2 -> L3 -> L4 -> L5 -> L6
- 同层能力模块默认禁止互调。
- 允许的跨能力协作由 L4 编排层显式组织。

### 3.3 模块差异化约束

- Gateway AuthControl：全局统一远程认证调用 + 限流控制点。
- 非 Gateway AuthControl：仅本地资源级限流，不做远程认证调用。
- SessionManager 与 TokenManager：仅认证中心持有，用于全局凭证状态管理。
- LocalCredentialManager：仅非认证中心模块持有（gateway/data_worker/普通服务），仅管理本模块自身外发凭证。
- ServiceResolver 与 PolicySnapshotManager：网关专属（用于目标服务解析与路由策略快照管理）。

### 3.4 协议角色分配（显式）

- gateway：External HTTP Server + Internal gRPC Client。
- certification_server：Internal gRPC Server。
- data_worker / 普通服务：Internal gRPC Server + Internal gRPC Client。
- 模块内部处理链可包含任务入口，但服务间 RPC 协议统一为 gRPC。

---

## 4. 统一能力拆分（跨模块一致）

### 4.1 统一流量站点

职责：

- 作为模块内唯一流量入口（入站/出站统一接入）。
- 承接标准化后的请求上下文。
- 委派通信下层执行分路与载荷流水线。

非职责：

- 不直接做认证策略决策。
- 不直接做通道生命周期管理。

### 4.2 通信下层（分路与载荷流水线）

职责：

- 基于 route_key / method / path / metadata 做流量分类。
- 输出目标服务类型、目标端点、策略标签。
- 根据策略调用载荷处理能力完成载荷准备与投递。

非职责：

- 不管理模块凭证生命周期。
- 不触发 bootstrap。

建议最小分类：

- bootstrap_call（后端模块对认证中心 bootstrap）
- remote_auth_verify（网关远程认证校验）
- external_auth_forward（网关转发外部 bootstrap/密码认证）
- business_forward（网关转发业务流量）

### 4.3 PayloadPipeline（独立模块）

职责：

- 载荷准备、头部整理、序列化与投递适配。
- 提供统一的请求/响应载荷整形能力。

非职责：

- 不做路由解析。
- 不做认证限流决策。
- 不承担通道状态管理。

### 4.4 Bootstrap + LocalCredentialManager（非认证中心模块）

Bootstrap 职责：

- 负责 challenge/bootstrap 的流程编排与凭证获取。
- 产出凭证后写入 LocalCredentialManager。

LocalCredentialManager 职责：

- 将 bootstrap 结果持久到 Redis 缓存。
- 写入成功确认后才允许返回 bootstrap 成功。
- 提供 ActiveCredential 查询与状态更新。
- 负责凭证失效、续期标记、撤销标记管理。

失败处理约束：

- Redis 写入失败必须向上层编排显式返回错误，不得静默吞错。
- 上层编排负责决策重试、降级或拒绝流程。

非职责（两者共同）：

- 不做限流决策。
- 不做额外安全准备。
- 不管理认证中心全局会话/令牌（该职责属于 SessionManager/TokenManager）。

### 4.5 AuthControl（收敛 RateLimit）

职责：

- AuthControl 内聚认证决策与限流决策，不再定义独立的 RateLimit 能力模块。
- Gateway：调用远程认证能力并根据认证结果执行限流。
- 非 Gateway：执行本地资源级限流（本地执行、与远程认证无关）。

非职责：

- 不调用 bootstrap。
- 不承担凭证状态管理。
- 不承担路由分流。
- 不承担业务流量转发后的远程复核。
- 不再拆分独立 ratelimit service/usecase 接口层。

建议统一返回语义：

- AuthVerified
- AuthRejected
- AuthUnavailable
- RateLimitAllowed / RateLimitDenied

### 4.6 已裁撤的 TargetReverify（历史）

- 目标服务独立复核能力与下游授权方案已在 2026-04-16 裁撤，不再作为现行设计。
- 现行目标服务仅保留本地 AuthControl 与业务处理链路。

### 4.7 底层数据管理模块（新增方向）

本节用于固定面向特定数据状态的底层模块分类，这些模块作为下层能力存在，供上层统一编排调用。

1. ServiceRegistryManager（服务注册/发现）

- 职责：实例注册、注销、发现、快照读取、存活筛选与实例选择。
- 边界：仅提供存活与路由筛选数据，不提供身份可信判定。

2. SessionManager（会话状态管理）

- 职责：会话创建、校验、续期、撤销、会话状态持久化。
- 边界：不负责令牌签发策略、不负责编排认证流程。
- 服务归属：仅 certification_server（全局凭证状态管理权威）。
- 方向：当前即使未独立实现，也应在接口与目录规划上预留独立位置。

3. TokenManager（令牌状态管理）

- 职责：签发结果落库、校验、撤销、刷新族管理。
- 边界：不负责会话主数据治理、不负责上层鉴权编排。
- 服务归属：仅 certification_server（全局凭证状态管理权威）。
- 方向：与 SessionManager 并列，避免混合成单一巨型服务。

4. KeyManager（密钥管理）

- 职责：本地密钥引用管理、公钥目录查询、激活密钥切换。
- 边界：不负责连接编排策略与业务限流策略。

5. ServiceResolver（服务类型/实例解析）

- 职责：内置路由映射策略，根据请求上下文解析目标服务类型与实例。
- 边界：不负责认证决策与凭证生命周期。
- 服务归属：仅 gateway。

6. LocalCredentialManager（本地凭证管理）

- 职责：管理 bootstrap 产出的本地凭证快照（Redis 主缓存）、读取与状态变更。
- 边界：不负责远程认证调用，不负责限流。
- 服务归属：gateway、data_worker、普通服务。

7. PolicySnapshotManager（网关专属）

- 职责：路由映射、运行模式、策略版本等配置快照管理。
- 价值：稳定上层编排输入，降低运行期策略漂移风险。
- 服务归属：仅 gateway。

---

## 5. 按模块设计草案

## 5.1 gateway

### 5.1.1 模块定位

- 外部请求统一入口与内部转发执行者。
- 在通信下层完成目标服务分类（含目标服务类型识别）。

### 5.1.2 目标层级

1. Inbound Adapter（HTTP）
2. Traffic Station（统一站点）
3. Routing + Payload Pipeline（通信下层）
4. Forwarding Orchestrator（上层行为决策）
5. Capability Modules
6. Data Managers（Registry/Key/Resolver/PolicySnapshot/LocalCredential）
7. Outbound Adapter（gRPC Client）

### 5.1.3 关键行为

- 无论是用户认证转发还是普通业务转发，均走同一 Traffic Station。
- 流量分类在通信下层完成，输出 TargetServiceType（由 ServiceResolver 内置路由映射策略支撑）。
- AuthControl 负责远程认证调用与限流决策，不管理凭证状态。
- 凭证状态由 LocalCredentialManager 管理；bootstrap 成功后写入 Redis。
- 协议固定：网关外部入站为 HTTP，网关内部出站调用统一为 gRPC client。

### 5.1.4 网关初始认证转发能力（补充）

- 网关必须支持将外部模块发起的 bootstrap/密钥校验请求转发到认证中心。
- 网关仅做转发与上下文封装，不本地执行认证中心权威逻辑。
- 认证中心本地持有并执行 bootstrap 与密钥校验能力。

### 5.1.5 网关业务流量转发（当前）

1. 网关收到外部业务请求并完成路由分类。
2. 网关按当前基线完成必要的转发准备并将流量送往目标服务，不再申请下游授权。
3. 目标服务先执行本模块 AuthControl（本地执行、无远程认证）。
4. 目标服务进入业务处理。

## 5.2 certification_server

### 5.2.1 模块定位

- 认证与全局凭证状态权威中心。
- 主要处理入站请求，不承担网关式转发。

### 5.2.2 目标层级

1. Inbound Adapter（gRPC Server）
2. Traffic Station（统一站点）
3. Routing + Payload Pipeline（通信下层）
4. Auth Request Orchestrator
5. Capability Modules（AuthControl / Bootstrap）
6. Data Managers（Registry/Session/Token/Key）
7. Repo/Storage

### 5.2.3 关键行为

- 认证请求统一进入 Traffic Station，再由通信下层分类。
- AuthControl 不承担远程认证调用，仅执行本地限流与认证结果消费。
- Bootstrap 负责签发链路；SessionManager 与 TokenManager 负责状态管理。
- certification_server 启动时加载本地单活密钥对，用于本模块自身认证与签名相关场景；该密钥对不通过 bootstrap 生成。
- 协议固定：认证中心对内统一暴露 gRPC server 作为权威入口。

## 5.3 data_worker

### 5.3.1 模块定位

- 任务消费与异步处理服务。
- 认证语义与普通服务一致，入口形态不同。

### 5.3.2 目标层级

1. Inbound Adapter（任务入口 + gRPC Server）
2. Traffic Station（统一站点）
3. Routing + Payload Pipeline（通信下层）
4. Worker Orchestrator
5. Capability Modules（AuthControl / Bootstrap）
6. Data Managers（Registry/Key/LocalCredential）
7. Repo/Queue
8. Outbound Adapter（gRPC Client）

### 5.3.3 关键行为

- 任务触发的跨服务调用与主动 bootstrap 调用都走统一站点。
- AuthControl 仅做本地资源级限流，不做远程认证调用。
- 凭证由 LocalCredentialManager 维护，bootstrap 成功后写入 Redis。
- data_worker 默认不持有 ServiceResolver 与 PolicySnapshotManager。
- no-auth 下由编排层统一短路认证要求。
- 协议固定：内部入站由 gRPC server 承接，内部出站统一由 gRPC client 发起。

## 5.4 普通服务模板（api_service 可复用）

定位与行为与 data_worker 一致，仅业务编排不同。

- 普通模块默认不直接暴露外部 HTTP 服务，外部流量经网关进入。
- 普通模块必须显式具备 gRPC server（被调用）与 gRPC client（主动调用）。

---

## 6. 系统通信类型总览（五类）

## 6.1 类型一：后端模块对认证中心的 bootstrap 请求

1. 认证中心外后端模块（gateway、data_worker、普通服务）发起 bootstrap。
2. 该流程先完成凭证获取。
3. bootstrap 成功后写入 Redis，由 LocalCredentialManager 接管。
4. 后端模块之外的外部 bootstrap/密码认证不纳入本类型，归入类型三。
5. 协议：发起方使用 gRPC client 调用认证中心 gRPC server。

## 6.2 类型二：网关向认证中心发起远程认证校验

1. 网关在转发或鉴权前触发远程认证校验。
2. 通信下层分类为 remote_auth_verify。
3. AuthControl 消费远程认证结果并执行限流决策。
4. 协议：网关以 gRPC client 调用认证中心 gRPC server。

## 6.3 类型三：网关转发外部 bootstrap/密码认证到认证中心

1. 网关接收外部模块的 bootstrap 或密码认证请求。
2. 通信下层分类为 external_auth_forward。
3. 网关将请求转发到认证中心 external_auth 通道。
4. 外部 bootstrap 固定通过 `ForwardBootstrapChallenge` + `ForwardBootstrapAuthenticate` 两步转发；不得复用网关自身 `bootstrap_call` 启动链路。
5. 外部用户名密码认证通过 `ForwardUserPassword` 转发。
6. 认证中心在本地执行 bootstrap/密钥校验/密码认证权威能力并返回结果。
7. 协议：外部到网关为 HTTP；网关到认证中心为 gRPC。

## 6.4 类型四：网关向目标服务转发业务流量

1. 网关接收外部业务请求并路由分类为 business_forward。
2. 网关将业务流量直接转发到目标服务。
3. 目标服务按自身业务链路处理请求。
4. 协议：外部到网关为 HTTP；网关到目标服务为 gRPC。

## 6.5 类型五：已裁撤的目标侧二次认证校验

1. target_reverify_call 已在 2026-04-16 裁撤。
2. 相关下游授权与目标侧复核链路不再作为现行设计。

---

## 7. 网关业务流量转发（流程细化）

协议前置：外部入口为 HTTP；网关与内部模块、内部模块之间统一为 gRPC。

1. Inbound：网关接收外部请求并标准化上下文。
2. Forward：网关完成路由分类后将请求转发到目标后端模块。
3. Local-Control：目标模块先执行本模块 AuthControl（本地资源级控制）。
4. Respond：目标模块返回结果，网关回传响应。

---

## 8. 横向调用约束矩阵（核心）

允许：

- 编排层 -> AuthControl
- 编排层 -> Bootstrap
- 编排层 -> LocalCredentialManager
- 编排层 -> PayloadPipeline
- Bootstrap -> LocalCredentialManager（写入 bootstrap 结果）
- Gateway AuthControl -> 远程认证客户端
- 通信下层 -> PayloadPipeline（仅为载荷处理与投递适配）
- gateway HTTP server -> gateway gRPC client（协议桥接）

禁止：

- AuthControl -> Bootstrap
- AuthControl -> PayloadPipeline
- AuthControl -> LocalCredentialManager（凭证状态管理逻辑禁止下沉到 AuthControl）
- Bootstrap -> AuthControl
- 非 Gateway AuthControl -> 远程认证调用
- 能力模块之间绕过编排层直接互调业务策略
- 内部模块间以 HTTP 直接互调业务接口

---

## 9. 最小接口草案（语义级）

### 9.1 Traffic Station

- HandleInbound(flow)
- SendOutbound(flow)

### 9.2 Routing + Payload Pipeline

- ResolveRoute(flow) -> RouteProfile
- ClassifyFlow(flow) -> FlowCategory
- BuildPayload(flow, RouteProfile) -> PayloadContext

RouteProfile 最小字段建议：

- target_service_type
- target_endpoint
- target_service_name
- flow_category（bootstrap_call / remote_auth_verify / external_auth_forward / business_forward）

### 9.3 AuthControl（按模块分语义）

说明：RateLimit 能力收敛在 AuthControl 内，不再单列独立能力接口。

Gateway AuthControl：

- VerifyRemoteAuth(ctx, authInput) -> AuthResult
- DecideRateLimit(ctx, verifiedIdentity) -> RateLimitDecision

非 Gateway AuthControl：

- DecideLocalRateLimit(ctx, localInput) -> RateLimitDecision

### 9.4 Bootstrap

- RunBootstrap(ctx, bootstrapInput) -> CredentialBundle

### 9.5 LocalCredentialManager（非认证中心模块）

- SaveBootstrapCredential(ctx, credentialBundle) -> RedisKey
- LoadActiveCredential(ctx, principal) -> CredentialSnapshot
- MarkCredentialExpired(ctx, principal)
- RevokeCredential(ctx, principal)

约束：

- SaveBootstrapCredential 返回成功才允许上层将 bootstrap 判定为成功。
- 失败必须返回可决策错误（供上层重试、降级或拒绝）。

### 9.6 TargetReverify（历史，已裁撤）

- 2026-04-16 之后不再保留独立目标侧复核接口。
- 若后续需要回溯该方案，仅作为历史草案参考。

### 9.7 PayloadPipeline

- PreparePayload(ctx, flow, routeProfile) -> PayloadContext
- AttachHeaders(ctx, payloadContext) -> PayloadContext
- FinalizeOutbound(ctx, payloadContext) -> PayloadContext

约束：

- 不做路由决策。
- 不做认证决策。
- 不承担凭证或会话状态管理。

### 9.8 ServiceRegistryManager

- Register(ctx, instance)
- Unregister(ctx, instanceID)
- Discover(ctx, serviceName, selector)
- Snapshot(ctx, serviceName)

### 9.9 SessionManager

- CreateSession(ctx, issueInput) -> Session
- ValidateSession(ctx, validateInput) -> SessionState
- RevokeSession(ctx, revokeInput)
- TouchSession(ctx, sessionID)

归属：仅 certification_server

### 9.10 TokenManager

- IssueTokenBundle(ctx, issueInput) -> TokenBundle
- VerifyToken(ctx, verifyInput) -> TokenState
- RefreshTokenBundle(ctx, refreshInput) -> TokenBundle
- RevokeToken(ctx, revokeInput)

补充：

- `RefreshTokenBundle` 已对应独立通信链路：gateway 外部转发使用 `AuthAuthorityExternalAuthService.ForwardRefreshTokenBundle`，模块自刷新使用 `AuthAuthorityTokenRefreshService.RefreshTokenBundle`。
- `RevokeToken` 仍保留在能力层接口，未单独冻结 route/proto。

归属：仅 certification_server

### 9.11 KeyManager

- LoadLocalKeyRef(ctx, owner)
- LookupPublicKey(ctx, query)
- SwitchActiveKey(ctx, owner, keyID)

### 9.12 ServiceResolver

- ResolveServiceType(ctx, flowInput) -> ServiceType
- ResolveTargetInstance(ctx, flowInput) -> TargetInstance
- ResolveRouteProfile(ctx, flowInput) -> RouteProfile

归属：仅 gateway

### 9.13 PolicySnapshotManager

- LoadPolicySnapshot(ctx, policySet) -> PolicySnapshot
- RefreshPolicySnapshot(ctx, policySet) -> PolicySnapshot
- GetRouteMappingVersion(ctx) -> string

归属：仅 gateway

---

## 10. 迁移建议（简版）

阶段 1：先做语义收敛（不改运行链）

- 将 AuthControl 中凭证状态管理语义迁出。
- 新增 LocalCredentialManager 接口与 Redis 缓存模型（非认证中心模块）。
- 认证中心保持 SessionManager + TokenManager 的全局凭证管理边界。

阶段 2：补齐 bootstrap -> Redis -> LocalCredentialManager 链路

- bootstrap 成功后强制写入 Redis。
- 非认证中心模块运行期凭证查询统一走 LocalCredentialManager。

阶段 3：拆分 AuthControl 两类实现

- Gateway AuthControl：远程认证 + 限流。
- 非 Gateway AuthControl：本地资源级限流。
- 清理独立 ratelimit 接口层定义并并入 AuthControl 门面。

阶段 4：补齐网关认证转发与业务转发链路

- 增加 external_auth_forward 路径。
- 增加 business_forward 的稳定转发与目标映射。

阶段 5：收敛目标侧复核方案

- 裁撤 target_reverify_call 分类与独立接口。
- 取消下游授权与目标侧二次认证校验的并行设计。

阶段 6：统一通信分类与可观测指标

- 按五类通信统一打点与审计字段。
- 同步固化协议维度打点：HTTP ingress（仅 gateway）与 gRPC internal RPC（全部内部调用）。

阶段 7：固化 no-auth 运行策略

- 禁用全部认证系统与额外安全准备。
- 认证中心默认屏蔽（或不启动），仅保留基础业务链路用于测试。

阶段 8：底层数据管理模块独立化

- 将 ServiceRegistryManager、SessionManager、TokenManager、KeyManager、ServiceResolver、PolicySnapshotManager、LocalCredentialManager 明确到独立目录与接口。
- 仅 certification_server 持有 SessionManager/TokenManager。
- 仅 gateway 持有 ServiceResolver/PolicySnapshotManager。
- gateway/data_worker/普通服务持有 LocalCredentialManager。
- 优先保持对外接口稳定，再逐步替换内部实现，避免触碰已稳定的 repo 对接实现。

---

## 11. 已确认决策（冻结）

1. 非 Gateway 模块不进行远程认证调用；Gateway AuthControl 承担全局统一认证校验和限流点。
2. bootstrap 凭证写入 Redis 必须成功；失败则上抛并通知上层决策。
3. external_auth_forward 直接转发外部 bootstrap/密码认证到认证中心。
4. business_forward 直接转发到目标服务，目标服务仅执行本模块 AuthControl 后进入业务处理，不再申请下游授权。
5. target_reverify_call 相关独立复核能力已裁撤，不再作为现行设计。
6. no-auth 模式禁用全部认证系统与额外安全准备，仅保留基础业务能力用于测试；认证中心默认被屏蔽（或不启动）。
7. RateLimit 能力收敛到 AuthControl，不再保留独立 ratelimit 能力接口层。
8. 协议角色冻结：gateway 外部 HTTP 入站 + 内部 gRPC 出站；certification_server 持有 gRPC server；普通内部模块同时持有 gRPC server/client；内部模块间不使用 HTTP。

## 12. 当前实现状态说明（过渡）

1. 当前 gateway 与 certification_server 的 usecase 层、service 层已有部分实现被删除，属于进行中的增量清理。
2. 本文档定义的是目标边界与分层方向，后续会继续执行更深层清理。
3. 后续清理原则：优先自顶向下收敛调用关系，不触碰已稳定的模型定义与 repo 直连基础实现。

下一步可直接进入：按模块输出目录与接口落地清单（可直接开工）。
