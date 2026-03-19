# API Service 模块设计说明（开发管控版）

## 1. 文档目的

本说明用于在后续开发中统一普通服务模块方向，避免因“既有 gRPC server 又要管理出站 gRPC client”导致职责交叉与引用失控。

文档覆盖：

- 整体架构与层级设计。
- 关键模块（接口/用例/适配器/模型）的职责划分。
- 启动链路、运行链路、限流链路与认证链路。
- 依赖约束与开发守则（防偏离清单）。

---

## 2. 当前定位与边界

### 2.1 API Service 定位

- 普通业务服务模块代表。
- 对外（对内网）提供 gRPC server 业务接口。
- 在必要时可向认证中心请求校验与认证续期。
- 可按业务需求调用其他内部服务（gRPC client 能力由统一 client hub 管理）。

### 2.2 明确非目标

- 不承担网关转发职责。
- 不承担认证中心授权签发职责。
- 不承担跨业务域聚合编排职责。

---

## 3. 分层架构

### 3.1 分层定义

1. App 层（应用生命周期与装配）

- 文件：src/app/app.py, src/app/lifecycle.py, main.py
- 职责：依赖装配、启动顺序、关闭顺序。

2. Usecase 层（业务编排）

- 文件：src/usecase/bootstrap/*, src/usecase/security/*, src/usecase/business/*, src/usecase/ratelimit/*
- 职责：定义调用链，不关心底层协议实现细节。

3. Service 层（领域能力）

- 文件：src/services/auth/*, src/services/commsec/*, src/services/communication/*, src/services/registry/*
- 职责：认证、通信安全、统一出站调用、注册与发现。

4. Adapter 层（协议适配）

- 文件：src/adapters/grpc/*
- 职责：gRPC server 启停与拦截器链、gRPC client 连接与复用管理。

5. Repo/Model/Utils 层

- 文件：src/repo/*, src/models/*, src/utils/*
- 职责：存储访问、领域模型、通用工具与密码学能力。

### 3.2 依赖方向（必须遵守）

- App -> Usecase -> Service -> Repo
- Usecase/Service 可依赖 Models
- Adapter 仅做协议适配与调用桥接
- 禁止反向依赖

---

## 4. 关键模块说明（按目录）

## 4.1 App 层

### 4.1.1 ServiceApp

- 文件：src/app/app.py
- 结构：
  - lifecycle（boot/shutdown）
  - grpc_server（start/stop）
- 作用：统一生命周期，确保先 boot 再 start，先 stop 再 shutdown。

### 4.1.2 HookLifecycle

- 文件：src/app/lifecycle.py
- 作用：可注入启动/关闭钩子，便于逐步替换为真实初始化逻辑。

---

## 4.2 gRPC Adapter 层

### 4.2.1 GrpcServerAdapter

- 文件：src/adapters/grpc/server_adapter.py
- 能力：
  - 服务注册回调管理
  - 启动/停止骨架
  - 拦截器链容器
- 作用：承载普通服务模块的 gRPC 入站边界。

### 4.2.2 GrpcClientHub

- 文件：src/adapters/grpc/client_hub.py
- 能力：
  - 按服务名维护 profile
  - 统一获取和复用 client
  - 连接预热与关闭
- 作用：统一管理各层出站 gRPC client，避免在业务层散落连接管理。

---

## 4.3 Usecase 层

### 4.3.1 ReadinessUsecase

- 文件：src/usecase/bootstrap/readiness_uc.py
- 依赖：BootstrapClient
- 作用：服务冷启动阶段 bootstrap 就绪编排。

### 4.3.2 PrepareOutboundSecurityUsecase

- 文件：src/usecase/security/prepare_outbound_security_uc.py
- 依赖：DownstreamGrantService, CommSecurityService
- 作用：出站前统一构建 grant/channel/encrypt 安全上下文。

### 4.3.3 HandleInboundGrpcUsecase

- 文件：src/usecase/business/handle_inbound_grpc_uc.py
- 依赖：PrepareOutboundSecurityUsecase
- 作用：统一入站业务编排与跨服务调用决策。

### 4.3.4 EnforceInboundUsecase（限流）

- 文件：src/usecase/ratelimit/enforce_inbound_uc.py
- 依赖：DescriptorFactory, RateLimiterService
- 作用：统一协议无关入站限流决策。

---

## 4.4 Service 层

### 4.4.1 认证与通信安全服务

- 文件：src/services/auth/*, src/services/commsec/*
- 作用：复用现有认证中心相关模型定义和本地安全能力。

### 4.4.2 OutboundInvokeService

- 文件：src/services/communication/outbound_invoke_svc.py
- 作用：统一发起对内 gRPC 出站调用，消费已准备好的安全上下文。

---

## 4.5 Repo 与模型层

### 4.5.1 Repo 基础客户端

- 文件：src/repo/mysql_client.py, src/repo/redis_store.py, src/repo/mongo_client.py, src/repo/etcd_client.py
- 作用：数据访问基础能力。

### 4.5.2 Model 层

- 文件：src/models/auth/*, src/models/commsec/*, src/models/registry/*, src/models/sys/*
- 作用：认证、安全、注册、系统配置与契约模型。

---

## 5. 核心调用关系

## 5.1 启动链（通用行为）

目标：完成普通服务模块就绪并开始提供 gRPC 服务。

建议顺序：

1. 加载配置。
2. 初始化 repo 客户端。
3. 初始化 GrpcClientHub 并注册下游服务 profile。
4. 执行 ReadinessUsecase（必要时向认证中心完成 bootstrap）。
5. 组装 gRPC server（注册 handler + 拦截器链）。
6. 启动 gRPC server。

## 5.2 运行链（职能行为）

目标：处理网关转发来的业务请求，并在必要时发起跨服务调用。

调用链：

1. gRPC 请求进入。
2. 限流与鉴权拦截器执行。
3. Handler 调用 HandleInboundGrpcUsecase。
4. 业务需要跨服务调用时，调用 PrepareOutboundSecurityUsecase。
5. OutboundInvokeService 通过 GrpcClientHub 发起调用。
6. 返回业务响应。

## 5.3 限流链（普通服务）

统一流程：

1. 拦截器提取上下文。
2. DescriptorFactory.Build -> RateLimitDescriptor。
3. RateLimiterService.Decide -> RateLimitDecision。
4. 若拒绝，返回 ResourceExhausted（gRPC）并附加 retry-after。

---

## 6. 约束清单（开发强约束）

1. Handler 不允许直接操作 repo 客户端。
2. Handler 不允许直接管理 gRPC client 连接。
3. GrpcClientHub 以服务名为唯一入口，禁止业务代码自行维护 channel。
4. 出站调用必须消费统一安全上下文，禁止绕过安全编排。
5. 限流规则匹配逻辑不允许放在拦截器本体。
6. 认证校验续期逻辑不允许散落在业务 handler。
7. 加密工具层不得主动发起网络调用。

---

## 7. 认证相关系统流程说明（冷启动 -> 稳定运行）

目标：让协作人员统一理解 gateway、certification_server、普通服务三类模块在认证生命周期内的行为。

### 7.1 Phase A：服务冷启动

1. 普通服务启动，初始化本地存储与 GrpcClientHub。
2. 普通服务通过 BootstrapClient 向认证中心申请 challenge。
3. 普通服务使用本地私钥签名 challenge，提交 bootstrap 认证。
4. 认证中心验证签名，签发 session/token，并返回 bootstrap ready。
5. 普通服务保存 bootstrap 结果，进入可服务状态。

### 7.2 Phase B：网关冷启动与安全预热

1. 网关启动后执行 readiness 流程，向认证中心完成自身 bootstrap。
2. 网关为关键下游服务预热 secure channel（可选）。
3. 网关注册服务实例并启动 HTTP server。

### 7.3 Phase C：初始流量进入

1. 外部请求进入网关。
2. 网关解析目标服务并向认证中心申请 downstream grant。
3. 网关确保与目标服务的 secure channel 可用，必要时发起握手。
4. 网关将请求转发至普通服务（附带授权与通道元数据）。
5. 普通服务入站拦截器执行限流与基础鉴权后进入业务处理。

### 7.4 Phase D：稳定运行

1. 网关持续复用已建立通道并按策略轮换。
2. 认证中心持续处理 token 校验、续期、撤销与握手请求。
3. 普通服务按需向认证中心请求校验/续期。
4. 三类服务均记录审计信息并输出限流/认证指标。

### 7.5 异常与恢复

- token 失效：普通服务或网关触发认证续期流程。
- 通道失效：网关或普通服务触发重新握手并更新通道。
- 限流触发：就地拒绝并返回协议侧重试信号，不绕过限流。
