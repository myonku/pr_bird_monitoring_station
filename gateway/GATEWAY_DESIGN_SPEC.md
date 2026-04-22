# Gateway 模块设计约束（硬约束版）

版本：1.0.0
状态：Constraint-Only
日期：2026-04-09

---

## 1. 目的

本文件只保留 gateway 的硬性约束和最小落地方向。

- 允许：作为实现与重构的约束清单。
- 禁止：作为历史设计说明或实现细节文档。

---

## 2. 模块角色与协议边界（冻结）

1. gateway 是外部请求统一入口和内部转发执行者。
2. gateway 对外协议固定为 HTTP server。
3. gateway 对内协议固定为 gRPC client。
4. 内部模块间禁止引入 HTTP 作为服务间协议。
5. gateway 不承担认证中心权威逻辑（会话/令牌全局状态、权威签发）。

---

## 3. 最小层级方向

gateway 只按以下最小层级收敛，不展开实现细节：

1. Inbound Adapter（HTTP）
2. Traffic Station（统一流量站点）
3. Routing + Payload Pipeline（通信下层）
4. Forwarding Orchestrator（流程编排）
5. Capability Modules
6. Data Managers
7. Outbound Adapter（gRPC client）

Capability Modules 最小集合：

- AuthControl（含 RateLimit）
- Bootstrap

Data Managers 最小集合：

- ServiceRegistryManager
- KeyManager
- ServiceResolver（网关专属）
- PolicySnapshotManager（网关专属）
- LocalCredentialManager（网关本地凭证）

---

## 4. 硬约束

1. 所有入站/出站流量都必须先进入 Traffic Station。
2. 流量分类必须在通信下层完成，不允许在顶层按 auth/business 直接分叉实现。
3. AuthControl 内聚认证决策与限流决策，不再单列独立 RateLimit 模块。
4. Gateway AuthControl 负责远程认证调用结果消费和限流决策。
5. AuthControl 不得调用 Bootstrap、LocalCredentialManager。
6. Bootstrap 成功判定依赖 LocalCredentialManager 写入 Redis 成功；写入失败必须上抛错误。
7. 业务转发必须先获取授权并确保通道可用，再执行加密转发。
8. 目标服务必须执行二次认证复核；该复核属于目标服务独立能力，不属于 gateway AuthControl。
9. no-auth 模式下必须禁用认证链路、限流与通道加密要求。
10. no-auth 模式下的 HTTP 认证入口必须在网关边界短路，不得继续向认证中心发起 sign-in、refresh-session、bootstrap 或 token refresh 转发。
11. 配置文件只允许在启动期读取一次，运行期按参数快照传递。

---

## 5. 最小链路

启动链（最小）：

1. 读取配置快照（一次性）。
2. 初始化基础依赖与 Data Managers。
3. 执行 Bootstrap 并落地本地凭证。
4. 注册服务实例。
5. 启动 HTTP server。

运行链（最小）：

1. HTTP 入站标准化。
2. Traffic Station 接管。
3. 通信下层完成路由分类与策略决策。
4. AuthControl（远程认证结果消费 + 限流）。
5. 通信下层负责载荷处理与出站准备。
6. gRPC client 出站转发。

no-auth 运行链在 HTTP 入站边界直接保留健康检查与业务转发，不开放认证入口。

---

## 6. 明确非目标

1. 不在本文件描述 handler、proto、repo、SDK 的实现细节。
2. 不在本文件保留旧版兼容链路或历史迁移叙事。
3. 不在本文件定义认证中心内部权威逻辑。

---

## 7. 规范引用

- SYSTEM_BACKEND_LAYER_REFACTOR_DRAFT.md
- SYSTEM_GLOBAL_BASELINE_DESIGN.md
- SYSTEM_AUTH_STARTUP_CHAIN_DESIGN.md
- SYSTEM_NO_AUTH_STARTUP_CHAIN_DESIGN.md
