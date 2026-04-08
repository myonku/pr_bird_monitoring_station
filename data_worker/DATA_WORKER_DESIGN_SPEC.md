# Data Worker 模块设计说明（开发管控版）

## 1. 文档目的

本说明用于在后续开发中统一 data_worker 方向，避免在任务处理链路中提前固化实现细节，并确保认证能力与普通服务模块保持一致。

文档覆盖：

- data_worker 的认证职责边界与模块定位。
- 认证链路、启动链路与运行期校验链路。
- 开发约束、观测指标与全局文档引用。

本说明暂不定义分层结构与目录分工；待后续重构方案确定后统一补充。

---

## 2. 当前定位与边界

### 2.1 Data Worker 定位

- 数据处理与异步任务消费模块（队列/流式任务/批处理任务）。
- 在认证域中与普通服务模块保持同等职责：
  - 负责本模块自身 bootstrap、token/session 持有与续期。
  - 内部请求默认执行回源认证中心校验。
  - 跨服务调用前确保 commsec 安全通道可用。
- 不承担认证中心签发权威职责，不管理他方请求主体凭证状态。

### 2.2 明确非目标

- 不承担网关外部请求接入与路由转发职责。
- 不承担认证中心 challenge/token/session/downstream grant 的权威管理职责。
- 不在本阶段固化任务编排框架与执行器细节。

### 2.3 全局规范引用

- 跨模块认证链路与启动链路见根目录 SYSTEM_AUTH_STARTUP_CHAIN_DESIGN.md。
- 全局统一约定见根目录 SYSTEM_GLOBAL_BASELINE_DESIGN.md。
- no-auth 与 development 对照见根目录 SYSTEM_NO_AUTH_STARTUP_CHAIN_DESIGN.md。

---

## 3. 认证与运行关键能力

### 3.1 Bootstrap 与凭证生命周期

- 启动阶段读取 worker_id、active_key_id、认证中心地址等认证相关配置。
- 使用本地单活密钥完成 challenge 签名 bootstrap，换取 session + access/refresh token。
- 运行期维护本模块凭证快照，优先走 refresh 续期；续期失败按策略回退 bootstrap。

### 3.2 回源认证校验能力

- 对入站任务上下文执行认证中心回源校验，最小校验集为：会话有效性 + 主体一致性。
- 对下游透传上下文仅作消费与验证，不作为本地放行依据。
- 认证校验失败必须快速失败并记录可观测错误，不得静默降级。

### 3.3 通信安全与限流能力

- 跨服务出站前必须确保 commsec 通道可用（预热复用或首跳 EnsureChannel 握手）。
- 握手失败时阻断出站调用，不得明文降级。
- 限流主体来源以认证中心复核后的 identity 为主，原始头仅作补充元信息。

### 3.4 no-auth 运行模式行为

- no-auth 下短路 bootstrap/session/token/downstream grant。
- 关闭回源认证、限流与 commsec 握手/加密要求。
- 保留最小任务消费与处理能力，仅用于开发联调。

---

## 4. 核心调用链路

### 4.1 认证链路（初始化 -> 获取长期令牌）

1. 初始化读取配置（worker_id、key_id、认证中心地址）。
2. 加载本地单活私钥与公钥引用。
3. 请求 challenge 并执行签名 bootstrap。
4. 获取会话与 access/refresh 令牌。
5. 维护本模块会话/令牌状态用于续期，不持久化他方请求主体凭证状态。
6. 任务处理前执行回源认证中心校验；跨服务出站前确保安全通道可用。

### 4.2 启动链路（初始化 -> 稳定运行）

1. 初始化配置、队列与存储依赖、必要客户端。
2. 执行 readiness（含 bootstrap 就绪）。
3. 按部署形态注册服务发现实例（如适用）。
4. 装配任务入口认证校验前置与限流前置。
5. 启动任务消费循环（或等价入站处理入口）。
6. 进入稳定运行，持续处理任务、执行跨服务调用与失败恢复。

### 4.3 运行链路（任务消费 -> 业务处理）

1. 任务进入消费入口并完成协议标准化。
2. 执行认证中心回源校验并注入 verified identity。
3. 基于 verified identity 执行限流与鉴权策略。
4. 执行业务处理与可选跨服务调用。
5. 返回处理结果并记录认证/限流/通道指标。

---

## 5. 开发约束与落地要求

1. 任务处理入口不得直接操作认证底层实现，认证流程由统一编排能力承接。
2. 任务处理入口不得直接管理通道握手，出站前置由统一安全能力承接。
3. 认证校验失败必须显式返回失败状态并进入可观测路径，禁止吞错放行。
4. 非认证中心模块不承担他方主体凭证管理，仅管理本模块凭证生命周期。
5. 后端模块间通信必须遵循“先 EnsureChannel 后业务调用”，禁止明文降级。

最小观测指标建议：

- authority_verify_failed_total
- authority_verify_timeout_total
- secure_channel_handshake_attempt_total
- secure_channel_handshake_failed_total
- secure_channel_reuse_total
