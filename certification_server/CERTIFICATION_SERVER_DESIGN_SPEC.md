# Certification Server 模块设计说明（开发管控版）

## 1. 文档目的

本说明用于在后续开发中统一认证中心方向，防止由底层能力扩展引发的职责漂移与引用失控。

文档覆盖：

- 整体架构与层级设计。
- 核心模块（接口/编排/适配器/模型）的职责边界。
- 启动链路、运行链路、限流链路的调用关系。
- 依赖约束与开发守则（防偏离清单）。

---

## 2. 当前定位与边界

### 2.1 Certification Server 定位

- 仅有一个入站协议：gRPC Server。
- 核心职能：回应其他服务发来的认证请求、握手请求、信息鉴定请求。
- 安全职责：认证签发、会话令牌管理、握手协商、通道状态管理、加解密与验签能力。

### 2.2 明确非目标

- 不承担主动对外调用编排职责（无高层 gRPC client 责任）。
- 不承担网关式流量转发职责。
- 不承担下游业务聚合编排职责。

---

## 3. 分层架构

### 3.1 分层定义

1. App 层（应用生命周期与装配）

- 文件：src/app/app.go, src/app/lifecycle.go, main.go
- 职责：依赖装配、启动顺序、关闭顺序。

2. Usecase / Orchestration 层（业务编排）

- 文件：src/interfaces/orchestration/*.go（当前为编排接口），后续可在 src/usecase/orchestration/* 落地实现。
- 职责：串联 auth/commsec 服务，定义流程级事务边界与调用次序。

3. Interface 层（端口契约）

- 文件：src/interfaces/**
- 职责：定义可替换边界（auth/commsec/orchestration/ratelimit/registry）。

4. Adapter 层（端口实现）

- 文件：src/adapters/grpc/**, src/services/**, src/repo/**
- 职责：gRPC 协议适配、服务实现、存储访问实现。

5. Model/Utils 层（领域模型与工具）

- 文件：src/models/**, src/utils/**
- 职责：数据结构、错误定义、纯密码学与通用工具能力。

### 3.2 依赖方向（必须遵守）

- App -> Usecase/Orchestration -> Interfaces -> Adapters
- Usecase/Orchestration 可依赖 Models
- Interfaces 可依赖 Models
- 禁止反向依赖

---

## 4. 关键模块说明（按目录）

## 4.1 App 层

### 4.1.1 CertificationApp

- 文件：src/app/app.go
- 结构：
  - Lifecycle（Boot/Shutdown）
  - GRPCServerPort（Start/Stop）
- 作用：统一应用生命周期，确保先 Boot 再 Start，先 Stop 再 Shutdown。

### 4.1.2 HookLifecycle

- 文件：src/app/lifecycle.go
- 作用：当前阶段可注入生命周期钩子，便于逐步替换为真实启动流程。

### 4.1.3 main

- 文件：main.go
- 现状：已连接 App + gRPC Server 骨架，作为顶层边界固定入口。

---

## 4.2 Auth 接口层

### 4.2.1 IBootstrapService

- 文件：src/interfaces/auth/bootstrap.go
- 方法：
  - InitChallenge
  - AuthenticateBootstrap
  - GetBootstrapStage
- 职责：认证中心冷启动认证原子能力。

### 4.2.2 ITokenService

- 文件：src/interfaces/auth/token_svc.go
- 方法：
  - IssueToken / IssueTokenBundle
  - RefreshTokenBundle / VerifyToken
  - RevokeToken / RevokeTokenFamily
- 职责：令牌签发、校验、撤销与轮换。

### 4.2.3 ISessionService

- 文件：src/interfaces/auth/session_svc.go
- 方法：
  - CreateSession / GetSession / TouchSession / ValidateSession
  - RevokeSession / RevokePrincipalSessions
- 职责：会话生命周期管理与一致性校验。

### 4.2.4 IDownstreamGrantService

- 文件：src/interfaces/auth/downstream_grant_svc.go
- 职责：签发下游授权上下文。

---

## 4.3 CommSec 接口层

### 4.3.1 ICommSecurityService

- 文件：src/interfaces/commsec/commsec_svc.go
- 关键方法：
  - InitHandshake / CompleteHandshake
  - UpsertChannel / GetChannel / RevokeChannel
  - EncryptByChannel / DecryptByChannel
- 职责：握手、通道、传输加解密核心能力。

### 4.3.2 ISecretKeyService

- 文件：src/interfaces/commsec/secret_key.go
- 职责：本地私钥引用与全局公钥目录查询（私钥原文不外泄）。

---

## 4.4 Orchestration 接口层

### 4.4.1 IBootstrapOrchestrator

- 文件：src/interfaces/orchestration/bootstrap_flow.go
- 方法：
  - StartFlow
  - FinishFlow
  - GetStage
- 作用：将 challenge、验签、session/token、可选 downstream grant 串为流程。

### 4.4.2 ICommSecurityOrchestrator

- 文件：src/interfaces/orchestration/secure_channel_flow.go
- 方法：
  - StartHandshakeFlow
  - FinishHandshakeFlow
  - EncryptForTransport / DecryptFromTransport
  - RevokeChannelFlow
- 作用：把协商策略、验签、派生、落地、传输前后处理统一为流程。

---

## 4.5 RateLimit 模块

### 4.5.1 限流端口

- 文件：src/interfaces/ratelimit/ratelimiter.go
- 能力：
  - IRateLimiter.Decide
  - IDescriptorFactory.Build
  - InboundRateLimitInput（协议无关输入）

### 4.5.2 描述符工厂

- 文件：src/interfaces/ratelimit/descriptor_factory_default.go
- 作用：把 gRPC 上下文映射为统一 RateLimitDescriptor。

### 4.5.3 限流用例

- 文件：src/usecase/ratelimit/enforce_inbound_uc.go
- 作用：执行 Build -> Decide -> 拒绝决策返回。

### 4.5.4 gRPC 拦截器接入

- 文件：src/adapters/grpc/ratelimit_interceptor.go, src/adapters/grpc/ratelimit_input_builder_default.go
- 作用：在 handler 前统一执行入站限流，拒绝映射为 ResourceExhausted。

---

## 4.6 gRPC Adapter 层

### 4.6.1 Server 适配器

- 文件：src/adapters/grpc/server.go
- 能力：
  - 支持地址配置
  - 支持 TLS
  - 支持 unary/stream 拦截器链
  - 支持服务注册回调
- 作用：承载认证中心唯一入站协议边界。

### 4.6.2 Handler 层（待补）

- 建议目录：src/adapters/grpc/handlers_*.go
- 职责：仅做协议映射与错误映射，调用 orchestration/usecase，不直接调用 repo。

---

## 4.7 Service 层

### 4.7.1 Auth Services

- 文件：src/services/auth/*.go
- 现状：已具备 mysql+redis+内存兜底的混合实现骨架。
- 职责：认证实体状态管理与持久化一致性。

### 4.7.2 CommSec Services

- 文件：src/services/commsec/*.go
- 现状：已具备握手与通道管理、签名校验与加解密基础路径。
- 职责：通信安全领域核心行为与数据状态维护。

---

## 4.8 Repo 与模型层

### 4.8.1 Repo 基础客户端

- 文件：src/repo/mysql_client.go, src/repo/redis_client.go, src/repo/etcd_client.go
- 作用：统一基础数据访问能力（超时、探活、熔断）。

### 4.8.2 Model 层

- 文件：src/models/auth/*, src/models/commsec/*, src/models/registry/*, src/models/system/*
- 作用：领域对象、契约对象、系统配置与错误定义。

---

## 5. 核心调用关系

## 5.1 启动链（通用行为）

目标：完成认证中心就绪并开始服务。

建议顺序：

1. 加载配置。
2. 初始化 repo 客户端（mysql/redis/etcd）。
3. 组装 auth/commsec/registry 服务。
4. 组装 orchestration 用例实现。
5. 组装 gRPC server（注册服务 + 拦截器链）。
6. 启动 gRPC server。

## 5.2 运行链（职能行为）

目标：处理入站 gRPC 请求并返回认证中心结果。

调用链：

1. gRPC Unary/Stream 请求进入。
2. 限流拦截器与其他拦截器执行。
3. Handler 将请求映射为 orchestration 请求。
4. Orchestrator 串联 auth/commsec 服务。
5. Service 完成状态更新与持久化。
6. Handler 映射响应并返回。

## 5.3 限流链（认证中心）

统一流程：

1. 拦截器提取上下文 -> InboundRateLimitInput。
2. DescriptorFactory.Build -> RateLimitDescriptor。
3. IRateLimiter.Decide -> RateLimitDecision。
4. 若拒绝：返回 ResourceExhausted，并附加 retry-after/ratelimit-rule-id。

---

## 6. 约束清单（开发强约束）

1. gRPC Handler 不允许直接调用 repo 客户端。
2. gRPC Handler 不允许直接拼接业务流程，必须调用 orchestration/usecase。
3. Interceptor 不允许直接依赖 mysql/redis；只通过用例端口调用。
4. Orchestrator 不允许 import 具体 repo/client 实现。
5. 限流规则匹配逻辑不允许放在拦截器本体。
6. 签名验签与加解密行为不允许散落在 handler 层。
7. 私钥原文不允许出本地安全边界。
