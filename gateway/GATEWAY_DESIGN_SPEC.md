# Gateway 模块设计说明（开发管控版）

## 1. 文档目的

本说明用于在后续开发中统一网关方向，避免出现“由下向上扩张导致边界失控”的问题。

文档覆盖：

- 整体架构与层级设计。
- 各细化模块（接口/用例/适配器/模型）的职责。
- 启动链路、运行链路、限流链路的调用关系。
- 依赖约束与开发守则（防偏离清单）。

---

## 2. 当前定位与边界

### 2.1 Gateway 定位

- 仅有一个入站协议：HTTP Server。
- 核心职能：将外部请求转发到内部服务。
- 安全职责：在转发前完成认证授权与应用层安全通道准备。

### 2.2 明确非目标

- 不承载 gRPC Server 业务端点。
- 不负责认证中心逻辑本体（仅通过客户端接口调用认证中心）。
- 不承载下游业务编排。

---

## 3. 分层架构

### 3.1 分层定义

1. App 层（应用生命周期与装配）

- 文件：src/app/app.go, src/app/lifecycle.go, main.go
- 职责：装配依赖、启动顺序、关闭顺序。

2. Usecase 层（业务编排）

- 文件：src/usecase/bootstrap/*, src/usecase/security/*, src/usecase/forwarding/*, src/usecase/ratelimit/*
- 职责：定义调用链，不关心底层协议和存储细节。

3. Interface 层（端口契约）

- 文件：src/interfaces/**
- 职责：定义可替换边界（auth/commsec/communication/ratelimit/registry）。

4. Adapter 层（端口实现）

- 文件：src/adapters/**, src/services/**, src/repo/**, src/http_server/**
- 职责：协议适配、客户端调用、存储访问。

5. Model/Utils 层（领域模型与工具）

- 文件：src/models/**, src/utils/**
- 职责：数据结构、错误定义、纯工具逻辑。

### 3.2 依赖方向（必须遵守）

- App -> Usecase -> Interfaces -> Adapters
- Usecase 可依赖 Models
- Interfaces 可依赖 Models
- 禁止反向依赖

---

## 4. 关键模块说明（按目录）

## 4.1 App 层

### 4.1.1 GatewayApp

- 文件：src/app/app.go
- 结构：
  - Lifecycle（Boot/Shutdown）
  - HTTPServerPort（Start/Stop）
- 作用：统一应用生命周期，确保“先 Boot 再 Start，先 Stop 再 Shutdown”。

### 4.1.2 HookLifecycle

- 文件：src/app/lifecycle.go
- 作用：当前阶段的可注入生命周期钩子，便于逐步替换为真实启动流程。

### 4.1.3 main

- 文件：main.go
- 现状：占位入口（noop HTTP server + HookLifecycle），用于先固定顶层边界。

---

## 4.2 Auth 接口层

### 4.2.1 IBootstrapClient

- 文件：src/interfaces/auth/bootstrap_cli.go
- 方法：
  - InitChallenge
  - AuthenticateBootstrap
  - GetBootstrapStage
- 职责：对认证中心的原子调用接口（客户端语义）。

### 4.2.2 IBootstrapFlowCoordinator

- 文件：src/interfaces/auth/bootstrap_flow.go
- 方法：
  - EnsureReady
- 职责：主动编排接口（stage 检查 -> challenge -> 本地签名 -> bootstrap 认证）。

### 4.2.3 IDownstreamGrantClient

- 文件：src/interfaces/auth/downstream_grant_client.go
- 方法：
  - IssueDownstreamGrant
- 职责：获取下游访问授权（grant）。

### 4.2.4 ISessionService / ITokenManager

- 文件：src/interfaces/auth/session_svc.go, src/interfaces/auth/token_manager.go
- 职责：会话与令牌状态的读取/刷新/验证能力。

---

## 4.3 CommSec 接口层

### 4.3.1 ICommSecurityService

- 文件：src/interfaces/commsec/commsec_svc.go
- 关键方法：
  - InitHandshake / CompleteHandshake
  - EnsureChannel（主动方确保可用通道）
  - UpsertChannel / GetChannel / RevokeChannel
  - EncryptForChannel / DecryptFromChannel
- 职责：对应用层加密通道做完整生命周期管理，并为拦截器提供加解密能力。

### 4.3.2 ISecretKeyService

- 文件：src/interfaces/commsec/secret_key.go
- 职责：密钥读取与公钥目录查询（私钥原文不外泄）。

---

## 4.4 Communication 接口层

### 4.4.1 IOutboundInvocationSecurity

- 文件：src/interfaces/communication/outbound_security.go
- 作用：将 auth + commsec 组合成单次出站安全上下文。

### 4.4.2 IOutboundTargetResolver

- 文件：src/interfaces/communication/target_resolver.go
- 作用：路由与目标服务解析（只解析，不做认证/握手/转发）。

### 4.4.3 IOutboundForwarder

- 文件：src/interfaces/communication/outbound_forwarder.go
- 作用：执行出站调用（仅消费已准备好的安全上下文）。
- 关键输入：
  - Endpoint
  - RPCMethod/Method
  - TimeoutMS
  - OutboundSecurityContext（Grant/Channel/EncryptedMeta）

---

## 4.5 Usecase 层

### 4.5.1 ReadinessUsecase

- 文件：src/usecase/bootstrap/bootstrap_readiness_uc.go
- 输入：ReadinessRequest
- 依赖：IBootstrapFlowCoordinator
- 输出：BootstrapAuthResult
- 作用：启动阶段 bootstrap 就绪编排。

### 4.5.2 PrepareOutboundSecurityUsecase

- 文件：src/usecase/security/prepare_outbound_security_uc.go
- 输入：OutboundInvocationRequest
- 依赖：
  - IOutboundAuthCoordinator
  - IOutboundChannelCoordinator
- 输出：OutboundInvocationContext
- 作用：获取 grant、确保通道、按需加密负载。

### 4.5.3 ForwardExternalRequestUsecase

- 文件：src/usecase/forwarding/forward_external_request_uc.go
- 输入：ForwardExternalRequest
- 依赖：
  - IOutboundTargetResolver
  - IOutboundInvocationSecurity
  - IOutboundForwarder
- 作用：端到端外部请求转发编排。

### 4.5.4 EnforceInboundUsecase（限流）

- 文件：src/usecase/ratelimit/enforce_inbound_uc.go
- 依赖：
  - IDescriptorFactory
  - IRateLimiter
- 输出：RateLimitDecision
- 作用：统一协议无关入站限流决策。

---

## 4.6 Adapter 层

### 4.6.1 GRPCOutboundForwarder

- 文件：src/adapters/outbound/grpc_forwarder.go
- 依赖：
  - IGRPCConnProvider
  - IGRPCPayloadCodec
- 行为：
  - 解析 RPCMethod/Method
  - 从 Endpoint 获取连接
  - 构造 metadata（grant/channel/encrypted 信息）
  - 调用 conn.Invoke
- 备注：为“最小可用骨架”，具体 proto 映射由 codec 实现。

### 4.6.2 RegistryService + DiscoveryAdapter

- 文件：src/services/registry/registry_svc.go, src/services/registry/dscovery_adapter.go
- 作用：
  - RegistryService：注册/注销/快照读取（基于 etcd）。
  - DiscoveryAdapter：实例选择（标签过滤、亲和、轮询）。

### 4.6.3 Repo 基础客户端

- 文件：src/repo/mysql_client.go, src/repo/redis_client.go, src/repo/etcd_client.go, src/repo/kafka_client.go
- 作用：提供统一基础数据访问能力（含超时、熔断、连接探活）。

### 4.6.4 HTTP Server 目录

- 文件：src/http_server/server.go, src/http_server/router.go, src/http_server/handler.go
- 现状：占位包；尚未接入用例调用。

---

## 4.7 Model 层

### 4.7.1 Auth 模型

- 文件：src/models/auth/auth.go, auth_contract.go, bootstrap.go, ratelimit.go
- 关键能力：
  - Identity/Session/Token 语义
  - Bootstrap 挑战与认证结构
  - 限流描述符/规则/决策结构

### 4.7.2 CommSec 模型

- 文件：src/models/commsec/commsec.go, commsec_contract.go
- 关键能力：
  - ECDHE 握手与协商结果
  - SecureChannel 生命周期
  - 加密消息元数据
  - Ensure/Encrypt/Decrypt 请求响应结构

### 4.7.3 Registry/System 模型

- 文件：src/models/registry/entry.go, src/models/system/config.go, src/models/system/errors.go
- 关键能力：
  - 服务实例信息
  - 全局配置定义
  - 统一错误类型

---

## 5. 核心调用关系

## 5.1 启动链（通用行为）

目标：完成网关就绪与安全预热。

建议顺序：

1. LoadConfig
2. 初始化 repo 客户端（mysql/redis/etcd/kafka）
3. 组装 registry/discovery/adapters
4. 执行 ReadinessUsecase（bootstrap）
5. 可选：预热关键下游通道（EnsureChannel）
6. 注册网关服务实例
7. 启动 HTTP Server

## 5.2 运行链（职能行为）

目标：接收 HTTP 请求并安全转发。

调用链：

1. HTTP Handler 接收请求并标准化为 ForwardExternalRequest
2. ForwardExternalRequestUsecase.Execute
3. Resolver.Resolve 得到 ServiceName/Endpoint/Timeout
4. SecurityPreparer.Prepare 得到 Grant/Channel/CipherText
5. OutboundForwarder.Forward 执行 gRPC 调用
6. 返回 OutboundForwardResponse 并映射 HTTP 响应

## 5.3 限流链（跨协议统一）

HTTP middleware 与 gRPC interceptor 共用：

1. 提取协议上下文 -> InboundRateLimitInput
2. DefaultDescriptorFactory.Build -> RateLimitDescriptor
3. IRateLimiter.Decide -> RateLimitDecision
4. 如果拒绝：
   - HTTP: 429 + Retry-After
   - gRPC: ResourceExhausted + metadata

---

## 6. 约束清单（开发强约束）

1. Handler 不允许直接调用 repo 客户端。
2. Handler 不允许直接调用 commsec/auth 低层接口。
3. OutboundForwarder 不允许内部触发 bootstrap 或握手编排。
4. Usecase 不允许 import 具体 grpc/http/mysql/redis 实现。
5. DescriptorFactory 不允许依赖网络/存储层。
6. 限流规则匹配逻辑不允许放在 middleware/interceptor。
7. 加密工具层不得主动发起网络调用。

---

## 7. 认证相关系统流程说明（冷启动 -> 稳定运行）

目标：明确网关在认证生命周期中的职责边界，以及与认证中心、普通服务模块的协作顺序。

### 7.1 Phase A：网关冷启动

1. 网关初始化 repo 与基础适配器。
2. 网关执行 ReadinessUsecase，向认证中心完成 bootstrap。
3. 网关根据配置预热关键下游 secure channel（可选）。
4. 网关注册自身实例并启动 HTTP server。

### 7.2 Phase B：初始请求进入

1. 网关接收外部 HTTP 请求并解析目标服务。
2. 网关向认证中心申请 downstream grant。
3. 网关确保对目标服务的 secure channel 可用，不可用时发起握手。
4. 网关按需加密负载并转发 gRPC 请求到普通服务。

### 7.3 Phase C：稳定运行

1. 网关复用既有 channel，按策略更新或重建。
2. 网关按请求上下文持续申请/复用 grant。
3. 网关在 token 失效或通道撤销时触发补偿流程（续期/重握手）。
4. 网关将限流与认证失败映射为统一外部响应语义。

### 7.4 与其他模块的协作边界

- 对认证中心：只调用认证与通信安全接口，不承载授权签发逻辑本体。
- 对普通服务：只做安全转发，不介入服务内部业务处理。
- 对限流：网关侧负责 inbound HTTP 限流，规则评估逻辑不进入 handler。
