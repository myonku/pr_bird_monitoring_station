# Data Worker 模块设计约束（硬约束版）

版本：1.0.0
状态：Constraint-Only
日期：2026-04-09

---

## 1. 目的

本文件只保留 data_worker 的硬性约束和最小落地方向。

- 允许：作为任务服务重构时的边界约束。
- 禁止：承载历史实现方案与细节描述。

---

## 2. 模块角色与协议边界（冻结）

1. data_worker 是任务消费与异步处理模块。
2. 作为普通内部模块，必须同时具备 gRPC server 与 gRPC client。
3. 模块间通信协议固定为 gRPC，不引入 HTTP 服务间调用。
4. data_worker 不承担认证中心权威职责。
5. data_worker 不承担网关外部入口职责。

---

## 3. 最小层级方向

data_worker 按以下最小层级收敛：

1. Inbound Adapter（任务入口 + gRPC server）
2. Traffic Station（统一流量站点）
3. Routing + Payload Pipeline（通信下层）
4. Worker Orchestrator（流程编排）
5. Capability Modules
6. Data Managers
7. Repo / Queue
8. Outbound Adapter（gRPC client）

Capability Modules 最小集合：

- AuthControl（含 RateLimit，且仅本地资源级控制）
- Bootstrap

Data Managers 最小集合：

- ServiceRegistryManager
- KeyManager
- LocalCredentialManager（本模块本地凭证）

---

## 4. 硬约束

1. 所有入站/出站流量都必须先进入 Traffic Station。
2. 流量分类必须在通信下层完成，能力层不得自行分流绕过。
3. AuthControl 内聚本地资源级认证控制与限流，不做远程认证调用。
4. AuthControl 不得调用 Bootstrap、LocalCredentialManager。
5. Bootstrap 成功判定依赖 LocalCredentialManager 写入 Redis 成功；失败必须上抛错误。
6. 跨服务调用必须先完成出站准备，再执行业务调用，禁止明文降级。
7. 当 data_worker 作为目标服务接收网关业务流量时，必须在本模块 AuthControl 之后直接进入业务处理。
8. no-auth 模式下必须禁用认证链路、限流与通道加密要求。
9. 配置文件只允许在启动期读取一次，运行期按参数快照传递。

---

## 5. 最小链路

启动链（最小）：

1. 读取配置快照（一次性）。
2. 初始化队列/存储/客户端与 Data Managers。
3. 执行 Bootstrap 并落地本地凭证。
4. 启动任务入口与 gRPC server。

运行链（最小）：

1. 入站任务或 gRPC 请求标准化。
2. Traffic Station 接管。
3. 通信下层分类。
4. AuthControl（本地控制 + 限流）。
5. 如需跨服务调用：由 gRPC client 出站。
6. 如为网关转发到本模块的业务流量：执行本模块 AuthControl 后再进入业务处理。

---

## 6. 明确非目标

1. 不在本文件定义任务执行框架、调度策略和业务算法细节。
2. 不在本文件保留旧版认证流程叙事。
3. 不在本文件定义认证中心权威模型或网关内部实现。

---

## 7. 规范引用

- SYSTEM_BACKEND_LAYER_REFACTOR_DRAFT.md
- SYSTEM_GLOBAL_BASELINE_DESIGN.md
- SYSTEM_AUTH_STARTUP_CHAIN_DESIGN.md
- SYSTEM_NO_AUTH_STARTUP_CHAIN_DESIGN.md
