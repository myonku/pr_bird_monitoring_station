# 后端路由与 Proto 基准约定（合并版）

版本：1.0.0
状态：Baseline
适用模块：gateway / certification_server / data_worker

## 1. 文档目的

本文件合并并替代以下两份冻结文档：

- `SYSTEM_ROUTE_MAPPING_STRATEGY_FREEZE.md`
- `SYSTEM_PROTO_MINIMAL_FREEZE.md`

用于为后端后续开发提供单一基准约定，避免“路由规则”和“协议边界”分散维护。

## 2. 约定范围

本文件覆盖：

1. bootstrap 最小链路所需 proto 服务边界。
2. 路由输入输出语义与匹配优先级。
3. route_key、flow_category、security_policy 的统一映射。
4. 模块侧最小职责分工与验收基线。

本文件不覆盖：

- 完整业务转发策略与细粒度授权票据生命周期。
- 认证中心全部 verify/refresh/revoke 的完整业务语义细节。
- commsec 全量协议细节（仅保留本阶段对路由安全策略的最小约束）。

## 3. Proto 最小边界（Bootstrap to Registry）

### 3.1 权威服务

- service：`AuthAuthorityBootstrapService`
- method：`InitBootstrapChallenge`
- method：`AuthenticateBootstrap`

### 3.2 方法语义

1. `InitBootstrapChallenge`
   - 输入：调用方实体信息 + 请求上下文。
   - 输出：challenge payload（至少包含 challenge_id、nonce、过期时间）。
2. `AuthenticateBootstrap`
   - 输入：challenge 原文 + 签名证明 + scopes/role 等最小控制字段。
   - 输出：bootstrap stage + 最小凭证快照（含 active_comm_key_id、issued/expires）。

### 3.3 标识与时间规范

- 唯一标识：UUID v4 字符串。
- 时间字段：epoch milliseconds（`*_ms`）。

### 3.4 实现接入约定

- 允许“生成桩”与“结构化动态调用（适配层）”并存。
- 无论采用哪种接入方式，均必须保证：
  1. 方法名与语义一致。
  2. 字段语义一致。
  3. 错误语义可映射为统一失败路径。

## 4. 路由输入输出语义

### 4.1 输入字段最小集合

- route_key
- transport
- method
- path
- source_service
- target_service_hint
- metadata

### 4.2 输出字段最小集合

- target_service_type
- target_service_name
- target_endpoint
- flow_category
- security_policy

认证中心可附加 `operation` 与 `metadata` 扩展字段，但不得改变上述核心语义。

## 5. 匹配优先级（强制）

路由解析顺序固定为：

1. route_key 精确命中。
2. transport + method + path 命中静态规则。
3. 可信内部调用场景下使用 target_service_hint 补充解析。
4. 无法命中时返回 unknown/显式失败，由上层拒绝。

安全边界：

- 外部请求不得依赖 target_service_hint 直接决定内部目标。
- Gateway 仍是外部到内部目标映射的唯一决策点。

## 6. 流量类别与策略基准

### 6.1 FlowCategory

- bootstrap_call
- remote_auth_verify
- external_auth_forward
- business_forward
- target_reverify_call

补充：

- certification_server 内部可保留 `commsec_call` 作为扩展分类。

### 6.2 SecurityPolicy

- required
- optional
- disabled

阶段规则：

- bootstrap_call 当前阶段默认 `optional`。
- no-auth 模式下认证相关流量默认 `disabled`。
- 后续阶段再按链路类型提升到 `required`。

### 6.3 TargetServiceType

- auth_authority
- internal_service
- unknown

## 7. Route Key 基线表

### 7.1 本阶段强制落地

1. `auth.bootstrap.challenge`
   - flow_category：bootstrap_call
   - target_service_type：auth_authority
   - target_service_name：certification_server
   - security_policy：optional

2. `auth.bootstrap.authenticate`
   - flow_category：bootstrap_call
   - target_service_type：auth_authority
   - target_service_name：certification_server
   - security_policy：optional

### 7.2 已预留（按计划逐步落地）

1. `auth.remote.verify.token`
2. `auth.remote.validate.session`
3. `auth.external.forward.user_password`
4. `business.forward.generic`
5. `auth.target.reverify.forwarded_context`

## 8. Method 与 Route Key 映射

bootstrap 固定映射：

- `InitBootstrapChallenge` -> `auth.bootstrap.challenge`
- `AuthenticateBootstrap` -> `auth.bootstrap.authenticate`

## 9. 模块职责基线

### 9.1 gateway

- 实现完整匹配优先级。
- 外部输入内部目标字段必须忽略或拒绝。
- 输出完整 RouteProfile 核心字段。

### 9.2 certification_server

- 对认证相关 route_key 做权威处理。
- 未识别 route_key 必须显式失败，不做宽松回退。
- 可保留 operation-centric 扩展字段，但不得破坏统一输入输出语义。

### 9.3 data_worker

- 至少支持 bootstrap_call 出站映射到 certification_server。
- 预留 route_key 可按阶段计划逐步补齐。

## 10. 观测与审计最小字段

每次路由决策至少记录：

- route_key
- flow_category
- target_service_type
- target_service_name
- security_policy
- matched_by（route_key/static/hint）
- route_mapping_version
- request_id
- trace_id

## 11. 兼容与变更规则

1. 对已发布字段仅允许向后兼容扩展。
2. 破坏性改动需升级版本并同步更新本文件。
3. 方法名、route_key、核心语义任一变更，必须同步更新启动链说明与阶段时间线文档。
