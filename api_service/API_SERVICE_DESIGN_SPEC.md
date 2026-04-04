# API Service 模块设计说明（开发管控版）

## 1. 文档目的

本说明用于在后续开发中统一普通服务模块方向，避免因“既有 gRPC server 又要管理出站 gRPC client”导致职责交叉与引用失控。

文档覆盖：

- 整体架构与层级设计。
- 关键模块（接口/用例/适配器/模型）的职责划分。
- 启动链路、运行链路与限流链路。
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

### 2.3 全局规范引用

- 认证链路与启动链路统一见根目录 `SYSTEM_AUTH_STARTUP_CHAIN_DESIGN.md`。
- ID 规范、密钥规范、配置生命周期规范统一见根目录 `SYSTEM_GLOBAL_BASELINE_DESIGN.md`。
- 本文档仅保留普通服务模块的层级、结构与接口职责说明。

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

## 7. 全局流程与约定引用

- 跨模块认证链路与启动链路见根目录 `SYSTEM_AUTH_STARTUP_CHAIN_DESIGN.md`。
- 全局统一约定见根目录 `SYSTEM_GLOBAL_BASELINE_DESIGN.md`。
- 边缘端认证/上传双通道接口契约见 `edge_server/EDGE_GATEWAY_CHANNEL_INTERFACE_CONTRACT.md`。
