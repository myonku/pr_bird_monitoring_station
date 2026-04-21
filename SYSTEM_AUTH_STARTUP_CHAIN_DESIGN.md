# 系统认证链路与启动链路总说明（按模块）

版本：1.3.1
状态：Baseline

## 1. 文档目的

本说明集中定义各模块两条核心链路：

- 认证链路：从初始化到获取长期令牌（长期令牌统一指 refresh token 或等价长期凭据）。
- 启动链路：从初始化到稳定运行。

适用模块：

- 网关（gateway）
- 数据处理模块（data_worker）
- 认证中心（certification_server）
- 客户端（client）
- 边缘端（edge_server）

约束说明：

- 网关与普通服务模块在认证主干上保持一致，网关仅额外承担外部请求转发职能。
- 认证中心不执行“自我认证”，不承担自身 bootstrap 流程，也不发起自身认证调用；其职责是处理来自 gateway、普通服务与边缘端的外部认证请求并签发认证结果。
- 认证中心不执行自身 bootstrap 认证，但仍需加载本地单活密钥对，用于本模块自身认证与签名相关场景；该密钥对不由 bootstrap 产出。
- 非认证中心模块（gateway、data_worker、edge_server）不管理“他方请求主体”的 challenge/session/token 状态，认证权威与公钥目录权威统一归属认证中心。
- 非认证中心模块需负责本模块自身凭证生命周期（bootstrap 结果持有、refresh；revoke 相关语义保留，不纳入当前通路）。
- 内部转发请求默认采用“网关回源认证中心校验 + 目标模块再次回源认证中心校验”的双端校验路径。
- 后端模块间通信遵循各模块既定内部调用链路与认证约束，本文件不再定义握手式通道阶段。
- 限流决策基于认证中心复核后的身份上下文执行。
- 认证中心只负责全局 bootstrap / 用户密码认证阶段的凭证签发、全局凭证管理，以及对 gateway 的远程认证调用作出权威响应；不承担自身 bootstrap 流程，也不发起自身认证调用。
- 认证中心自身凭证不纳入当前设计边界，本轮不讨论自签发、自持有或自管理。
- 统一标识、密钥与配置规范以 `SYSTEM_GLOBAL_BASELINE_DESIGN.md` 为准。

---

## 2. 全局前提

1. 所有实体 ID 与唯一标识统一使用 UUID v4。
2. 客户端之外模块采用本地单活密钥对（私钥 PKCS#8 PEM，公钥 SPKI PEM）。
3. 模块级 ID 与唯一标识从配置文件在初始化阶段读取，本地文件名固定、路径可配置；bootstrap 引用ID优先使用 `active_key_id`，缺失时回退到 `instance_id`（边缘端对应 `device_id`）。
4. 用户实体 ID 仅在认证后由后端返回并透传。
5. 服务端与边缘端配置文件只在初始化读取一次，运行期参数传递。

---

## 3. 网关（Gateway）

### 3.1 认证链路（初始化 -> 获取长期令牌）

1. 初始化读取配置（gateway_id、key_id、认证中心地址、路由策略）。
2. 加载本地单活私钥与公钥引用。
3. 调用认证中心 challenge 初始化接口。
4. 对 challenge 载荷签名并提交 bootstrap 认证。
5. 认证中心验签通过后返回统一凭证结果结构；当前实现以 TokenBundle 作为核心令牌子集，必要时可附加身份、会话与时间信息。
6. 网关进入 ready，维护本模块自身会话与统一凭证结果结构用于续期，不持久化他方请求主体凭证状态。
7. 运行期 verify/refresh 统一转发认证中心，refresh 续期对应独立 token_refresh 通信链路；revoke 相关语义保留，不冻结独立 route/proto。网关仅消费结果执行转发与限流。
8. 运行期下游调用前完成目标地址、路由与认证上下文准备，按调用链路执行转发。
9. 内部转发阶段由网关注入下游认证上下文（至少 `x-downstream-principal`、`x-downstream-session-id`、`x-downstream-token-id`），供目标模块向认证中心再次校验。

### 3.2 启动链路（初始化 -> 稳定运行）

1. 初始化配置、repo 客户端、服务发现与路由组件。
2. 完成自身 bootstrap 就绪检查（Readiness）。
3. 将自身注册至服务发现中心。
4. 完成关键依赖与路由准备；若相关认证准备未完成，则在首跳转发前完成补齐。
5. 启动 HTTP 入站服务。
6. 进入稳定运行，持续执行转发、限流、鉴权、下游认证上下文透传与失败恢复。

### 3.3 相对普通服务的唯一新增职责

- 在完成同等认证主干能力基础上，额外承担“外部请求接收与转发”职责。

---

## 4. 普通服务模块（API Service）

### 4.1 认证链路（初始化 -> 获取长期令牌）

1. 初始化读取配置（service_id、key_id、认证中心地址）。
2. 加载本地单活私钥与公钥引用。
3. 请求 challenge 并执行签名 bootstrap。
4. 获取会话与 access/refresh 令牌。
5. API Service 维护本模块自身会话/令牌状态用于续期，不持久化他方请求主体凭证状态。
6. 内部转发默认执行回源认证中心校验（至少会话校验，按场景补充令牌校验）。

### 4.2 启动链路（初始化 -> 稳定运行）

1. 初始化配置、存储客户端、gRPC 客户端中心。
2. 执行 readiness（含 bootstrap 就绪）。
3. 将自身注册至服务发现中心。
4. 装配 gRPC handler 与拦截器链（含认证中心回源校验拦截器）。
5. 启动 gRPC server 对内提供业务能力。
6. 进入稳定运行，处理业务请求与跨服务调用，并基于回源复核后的身份执行限流。

---

## 5. 数据处理模块（Data Worker）

### 5.1 认证链路（初始化 -> 获取长期令牌）

1. 初始化读取配置（worker_id、key_id、认证中心地址）。
2. 加载本地单活私钥与公钥引用。
3. 请求 challenge 并执行签名 bootstrap。
4. 获取会话与 access/refresh 令牌。
5. Data Worker 维护本模块自身会话/令牌状态用于续期，不持久化他方请求主体凭证状态。
6. 入站任务处理默认执行回源认证中心校验（至少会话校验，按场景补充令牌校验）。

### 5.2 启动链路（初始化 -> 稳定运行）

1. 初始化配置、队列/存储客户端、必要出站客户端。
2. 执行 readiness（含 bootstrap 就绪）。
3. 按部署形态将自身注册至服务发现中心（如适用）。
4. 装配任务处理入口与拦截器链（含认证中心回源校验前置）。
5. 启动任务消费循环（或等价入站处理入口）。
6. 进入稳定运行，处理任务与跨服务调用，并基于回源复核后的身份执行限流。


---

## 6. 认证中心（Certification Server）

### 6.1 认证处理链路（对外响应，不含自认证）

1. 初始化认证策略、签发参数、密钥目录与存储依赖。
2. 认证中心只对外响应外部认证请求：接收来自 gateway、普通服务与边缘端的 challenge 初始化、用户名密码认证及其他认证调用，不承担自身 bootstrap 流程，也不发起自身认证调用。
3. 接收签名证明并执行公钥目录校验与验签。
4. 创建会话并签发统一凭证结果结构；当前实现以 TokenBundle 作为核心令牌子集（access token + refresh token，按场景可选 downstream token），必要时可附加身份、会话、active_comm_key_id、issued_at、expires_at 等上下文。
5. 提供 verify/refresh 等持续认证服务，其中 refresh 已冻结为独立 token_refresh 通信链路，供 gateway 外部转发与模块侧自刷新复用；revoke 相关语义保留。

说明：

- 认证中心不需要也不执行自身 bootstrap 认证。

### 6.2 启动链路（初始化 -> 稳定运行）

1. 初始化配置、本地单活密钥对（固定文件名、路径可配置）、mysql/redis/etcd 等基础依赖。
2. 组装 auth/ratelimit/orchestration 组件。
3. 启动 gRPC server 并挂载拦截器。
4. 进入稳定运行，持续处理认证与通信安全请求。

---

## 7. 客户端（Client）

### 7.1 认证链路（初始化 -> 获取长期令牌）

1. 初始化读取客户端配置（client_id、网关地址、设备信息）。
2. 调用网关登录接口提交用户名/密码。
3. 网关转发认证中心校验后返回会话与令牌。
4. 客户端获取统一凭证结果结构；当前实现以 TokenBundle 作为核心令牌子集（access token + refresh token，长期令牌）。
5. 运行期用 refresh token 续期；续期失败则回到登录流程。

说明：

- 上述 refresh 语义现已对应独立 token_refresh 通信链路：gateway 外部转发可走 `AuthAuthorityExternalAuthService.ForwardRefreshTokenBundle`，模块侧自刷新可走 `AuthAuthorityTokenRefreshService.RefreshTokenBundle`。
- revoke 相关语义保留，不冻结独立 route/proto。

### 7.2 启动链路（初始化 -> 稳定运行）

1. 初始化 UI/本地状态与网关连接参数。
2. 检查本地是否存在可用 refresh token。
3. 可续期则静默续期，不可续期则引导登录。
4. 登录成功后进入稳定运行，发起业务请求并处理 401/403 恢复。

---

## 8. 边缘端（Edge Server）

### 8.1 认证链路（初始化 -> 获取长期令牌）

1. 初始化读取配置（device_id、key_id、gateway 认证地址）。
2. 加载本地单活密钥并恢复本地认证状态（若存在）。
3. 若无可用状态，发起 challenge 并提交签名 proof。
4. 通过网关转发认证中心，获取统一凭证结果结构；当前实现以 TokenBundle 作为核心令牌子集（access token + refresh token，长期令牌）。
5. 运行期由认证协调器维护 ensure_ready/refresh；revoke 相关语义仅作保留。

### 8.2 启动链路（初始化 -> 稳定运行）

1. 初始化配置、采集模块、推理模块、上传模块、本地 spool。
2. 初始化认证协调器并确保可生成认证头。
3. 启动主流程循环（采集 -> 决策 -> 推理 -> 上传）。
4. 启动补传 worker，异步清理离线积压。
5. 进入稳定运行，网络波动时执行重试与认证恢复。

---

## 9. 文档关系与落地要求

- 本文档负责“按模块链路视角”的统一说明。
- no-auth 启动链路与 development 对照说明见 `SYSTEM_NO_AUTH_STARTUP_CHAIN_DESIGN.md`。
- 边缘端接口字段与 HTTP 契约统一见 `SYSTEM_EXTERNAL_INTERFACE_CATALOG_DESIGN.md`，落地实现以边缘模块内现有代码与全局基线约束为准。
- 全局规范（UUID、密钥、配置生命周期）以 `SYSTEM_GLOBAL_BASELINE_DESIGN.md` 为准。
- 模块设计文档仅保留层级/结构/接口职责，不再承载认证链路叙事。
- 内部转发链路若出现歧义，以“双端回源认证中心校验”为准。
- 后端模块间通信若出现歧义，以“双端回源认证中心校验”为准。

---

## 10. 后端启动链执行细则（development 补充）

本节用于补充后端模块在 development 模式下的统一执行细则，作为跨模块落地时的最小一致性约束。

### 10.1 统一顺序（后端三模块）

1. 读取配置快照（仅一次）。
2. 规范化运行时标识（entity_type、service_name、instance_id、端口、run_mode）。
3. 初始化基础依赖（至少 etcd 客户端与注册服务）。
4. 初始化本地密钥服务并解析有效 bootstrap 引用ID（优先 active_key_id，缺失时回退 instance_id；边缘端对应 device_id）。
5. 执行模块级 bootstrap 分支：
	- gateway/data_worker：执行 bootstrap readiness 链路。
	- certification_server：明确跳过自身 bootstrap。
6. 构造 ServiceInstance 元数据。
7. 调用注册服务写入服务发现。
8. 启动最小入站能力并进入运行态。

### 10.2 失败处理约束

- 配置解析失败：立即失败退出，不注册。
- 依赖初始化失败：立即失败退出，不注册。
- bootstrap 分支失败（gateway/data_worker）：立即失败退出，不注册。
- 注册失败：立即失败退出，不进入最小运行态。
- 注册成功后入站启动失败：必须 best-effort 注销实例后退出。

### 10.3 注册实例与键路径约束

注册实例最小字段：

- id
- service_id
- name
- endpoint
- heartbeat
- weight
- tags
- active_comm_key_id
- metadata

补充规则：

- heartbeat 为空时由注册服务填充当前毫秒时间。
- weight 小于等于 0 时归一为 1。
- 注册键路径统一为 `/bms/services/{service_name}/{instance_id}`。

### 10.4 阶段日志最小集

每个后端模块至少输出以下阶段日志：

- config_loaded
- dependencies_initialized
- bootstrap_skipped_or_ready
- registry_register_attempt
- registry_register_success
- server_start_attempt
- server_start_success

失败路径至少记录：

- stage
- error
- request_id 或 trace_id（若可用）

### 10.5 文档引用补充

- 路由与 proto 合并基准见 `SYSTEM_BACKEND_ROUTE_PROTO_BASELINE.md`。
- 后端启动链路阶段记录与时间线见 `SYSTEM_BACKEND_PROGRESS_TIMELINE.md`。
