# Certification Server 模块设计约束（硬约束版）

版本：1.0.0
状态：Constraint-Only
日期：2026-04-09

---

## 1. 目的

本文件只保留 certification_server 的硬性约束和最小落地方向。

- 允许：作为认证中心重构边界与验收依据。
- 禁止：承载历史流程说明和实现细节。

---

## 2. 模块角色与协议边界（冻结）

1. certification_server 是认证与通道协商权威中心。
2. 入站协议固定为 gRPC server。
3. 不承担网关式流量转发职责。
4. 不承担外部 HTTP 服务入口职责。
5. SessionManager 和 TokenManager 仅认证中心持有。

---

## 3. 最小层级方向

认证中心按以下最小层级收敛：

1. Inbound Adapter（gRPC server）
2. Traffic Station（统一流量站点）
3. Routing + Payload Pipeline（通信下层）
4. Auth Request Orchestrator（流程编排）
5. Capability Modules
6. Data Managers
7. Repo / Storage

Capability Modules 最小集合：

- AuthControl（含 RateLimit）
- Bootstrap（权威能力）
- CommsecChannelManager

Data Managers 最小集合：

- ServiceRegistryManager
- KeyManager
- SessionManager（认证中心专属）
- TokenManager（认证中心专属）

---

## 4. 硬约束

1. 所有认证请求和通道请求都必须先进入 Traffic Station。
2. 通信下层负责流量分类，能力层不得绕过该分类自行分叉。
3. AuthControl 内聚认证决策结果消费和限流决策，不再单列独立 RateLimit 模块。
4. AuthControl 不得调用 Bootstrap 或 CommsecChannelManager。
5. CommsecChannelManager 只做通道生命周期与载荷处理，不做认证策略决策。
6. 认证中心必须提供 bootstrap、remote_auth_verify、external_auth_forward、target_reverify_call 对应权威处理能力。
7. gRPC handler 不得直连 repo，必须通过编排层/能力层端口。
8. no-auth 模式下认证中心默认屏蔽或不启动。
9. 配置文件只允许在启动期读取一次，运行期按参数快照传递。

---

## 5. 最小链路

启动链（最小）：

1. 读取配置快照（一次性）。
2. 初始化基础依赖与 Data Managers。
3. 组装认证与通道能力。
4. 启动 gRPC server。

运行链（最小）：

1. gRPC 入站标准化。
2. Traffic Station 接管。
3. 通信下层分类。
4. AuthControl（本地控制 + 限流）。
5. 调用 Bootstrap/Session/Token/Commsec 等权威能力。
6. 返回权威结果。

---

## 6. 明确非目标

1. 不在本文件描述 proto 映射、数据库表结构和密码学实现细节。
2. 不在本文件保留旧版编排接口叙事。
3. 不在本文件定义网关或普通模块内部实现。

---

## 7. 规范引用

- SYSTEM_BACKEND_LAYER_REFACTOR_DRAFT.md
- SYSTEM_GLOBAL_BASELINE_DESIGN.md
- SYSTEM_AUTH_STARTUP_CHAIN_DESIGN.md
- SYSTEM_NO_AUTH_STARTUP_CHAIN_DESIGN.md
