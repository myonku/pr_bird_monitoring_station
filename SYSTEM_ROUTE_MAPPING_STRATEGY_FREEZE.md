# 后端路由映射策略冻结说明

状态：Frozen-Minimal
阶段：Bootstrap to Registry
适用模块：gateway / certification_server / data_worker

## 1. 目标

本文件冻结后端最小可实施的路由映射策略，服务于当前阶段目标：

- 不实现完整业务转发链路。
- 先保证 bootstrap 最小链路的路由决策一致。
- 为后续注册启动链和实现层落地提供唯一策略基线。

## 2. 输入与输出冻结

### 2.1 统一输入模型

跨模块路由输入统一使用以下字段语义：

- route_key
- transport
- method
- path
- source_service
- target_service_hint
- metadata

### 2.2 统一输出模型

路由输出最小集合冻结为：

- target_service_type
- target_service_name
- target_endpoint
- flow_category
- security_policy

认证中心内部路由画像可继续使用 operation 和 metadata 字段，但不得改变以上核心语义。

## 3. 匹配优先级冻结

解析顺序严格固定为：

1. route_key 精确命中。
2. transport + method + path 命中静态规则。
3. 可信内部调用场景下，使用 target_service_hint 做补充解析。
4. 无法命中时返回 unknown，并交由上层拒绝或显式失败。

强制约束：

- 外部请求不得依赖 target_service_hint 直接决定内部目标服务。
- 网关仍是外部请求到内部目标服务的唯一决策点。

## 4. 服务类型冻结

TargetServiceType 仅允许：

- auth_authority
- internal_service
- unknown

服务名冻结为当前模块配置中使用的规范值：

- certification_server
- gateway
- data_worker

## 5. FlowCategory 冻结

跨模块统一使用下列五类：

- bootstrap_call
- remote_auth_verify
- external_auth_forward
- business_forward
- target_reverify_call

补充：

- certification_server 内部保留 commsec_call 作为认证中心侧扩展分类。
- 本阶段不要求其他模块实现 commsec_call。

## 6. SecurityPolicy 冻结

统一值：

- required
- optional
- disabled

阶段规则：

- 当前阶段 bootstrap_call 使用 optional，优先保障最小链路联通。
- no-auth 模式下认证相关流量默认 disabled。
- 下一阶段再将特定链路提升到 required。

## 7. Route Key 冻结表（本阶段）

### 7.1 已冻结且立即生效

1) auth.bootstrap.challenge

- flow_category: bootstrap_call
- target_service_type: auth_authority
- target_service_name: certification_server
- security_policy: optional
- 说明：对应认证中心 challenge 初始化。

2) auth.bootstrap.authenticate

- flow_category: bootstrap_call
- target_service_type: auth_authority
- target_service_name: certification_server
- security_policy: optional
- 说明：对应认证中心 bootstrap 认证。

### 7.2 已预留但本阶段不强制实现

1) auth.remote.verify.token

- flow_category: remote_auth_verify
- target_service_type: auth_authority
- target_service_name: certification_server
- security_policy: required

2) auth.remote.validate.session

- flow_category: remote_auth_verify
- target_service_type: auth_authority
- target_service_name: certification_server
- security_policy: required

3) auth.external.forward.user_password

- flow_category: external_auth_forward
- target_service_type: auth_authority
- target_service_name: certification_server
- security_policy: required

4) business.forward.generic

- flow_category: business_forward
- target_service_type: internal_service
- target_service_name: 由策略映射决策
- security_policy: required

5) auth.target.reverify.forwarded_context

- flow_category: target_reverify_call
- target_service_type: auth_authority
- target_service_name: certification_server
- security_policy: required

## 8. 模块级路由职责

### 8.1 gateway

- 必须实现完整匹配优先级。
- 对外流量进入时必须忽略或拒绝外部提供的内部目标服务字段。
- 输出 RouteProfile 时填充 target_service_type 和 target_service_name。

### 8.2 certification_server

- 作为 auth_authority，只对认证相关 route_key 做权威处理。
- 对无法识别的 route_key 显式返回错误，不做宽松回退。
- commsec_call 仅作为本模块保留扩展入口。

### 8.3 data_worker

- 当前阶段至少支持 bootstrap_call 出站映射到 certification_server。
- 其余预留 route_key 可先返回未实现错误。

## 9. Policy Snapshot 约定

gateway 的策略快照至少包含：

- policy_set
- runtime_mode
- route_mapping_version
- route_mappings

route_mapping_version 建议格式：

- YYYYMMDD.N

## 10. 观测与审计最小字段

每次路由决策至少记录：

- route_key
- flow_category
- target_service_type
- target_service_name
- security_policy
- matched_by（route_key 或 fallback）
- route_mapping_version
- request_id
- trace_id

## 11. 与 Proto 冻结联动

与 SYSTEM_PROTO_MINIMAL_FREEZE.md 保持一致：

- auth.bootstrap.challenge 对应 InitBootstrapChallenge。
- auth.bootstrap.authenticate 对应 AuthenticateBootstrap。

若 proto 方法名或消息边界调整，必须同步更新本文件并递增 route_mapping_version。

## 12. 本阶段验收标准

- 三模块对 bootstrap 两条 route_key 的分类和目标解析一致。
- 无歧义回退路径，未知 route_key 必须显式失败。
- 不实现完整业务转发也不影响当前阶段推进。
