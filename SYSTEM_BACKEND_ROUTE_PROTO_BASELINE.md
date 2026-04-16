# 后端路由与 Proto 基准约定（合并版）

版本：1.4.0
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
3. route_key、flow_category、target_service_type、target_service_name 的统一映射。
4. 模块侧最小职责分工与验收基线。

本文件不覆盖：

- 完整业务转发策略与细粒度授权票据生命周期。
- 认证中心全部 verify/refresh/revoke 的完整业务语义细节。
- 底层传输实现细节（仅保留本阶段对路由边界的最小约束）。

## 3. Proto 最小边界（Bootstrap 与内部认证 RPC）

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

### 3.5 本轮已补齐的内部认证 RPC

- `AuthAuthorityRemoteAuthService`
   - `VerifyToken`
   - `ValidateSession`
- `AuthAuthorityExternalAuthService`
   - `ForwardUserPassword`
   - `ForwardBootstrapChallenge`
   - `ForwardBootstrapAuthenticate`

说明：

- 以上 RPC 已接入认证中心 gRPC 注册链，并在 gateway / data_worker 侧补齐最小 client 或调用适配。
- 其中 remote_auth、external_auth 保持现行最小实现；target_reverify 与 downstream grant 相关设计已于 2026-04-16 裁撤，不再纳入当前基线。
- 本轮 external_auth 的外部 bootstrap 转发修补只涉及 gateway 与 certification_server，不扩散到其他模块。

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

补充：

- target_reverify_call 已裁撤，不再作为现行 FlowCategory。

- certification_server 内部可保留额外实现分类，但不在本文件中定义新的安全策略字段。

### 6.2 运行模式约束

- bootstrap_call 当前阶段保持最小可用。
- no-auth 模式下认证相关流量按关闭认证链处理。
- 后续阶段如需更细路由策略，由模块级文档或实现配置补充。

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
2. `auth.bootstrap.authenticate`

   - flow_category：bootstrap_call
   - target_service_type：auth_authority
   - target_service_name：certification_server

### 7.2 已落地的最小通路

1. `auth.remote.verify.token`

   - flow_category：remote_auth_verify
   - target_service_type：auth_authority
   - target_service_name：certification_server
2. `auth.remote.validate.session`

   - flow_category：remote_auth_verify
   - target_service_type：auth_authority
   - target_service_name：certification_server
3. `auth.external.forward.user_password`

   - flow_category：external_auth_forward
   - target_service_type：auth_authority
   - target_service_name：certification_server
4. `auth.external.forward.bootstrap.challenge`

   - flow_category：external_auth_forward
   - target_service_type：auth_authority
   - target_service_name：certification_server
5. `auth.external.forward.bootstrap.authenticate`

   - flow_category：external_auth_forward
   - target_service_type：auth_authority
   - target_service_name：certification_server

补充：以上 route_key 已完成最小 RPC 通路与静态路由对齐，仍保持业务逻辑最小实现。target_reverify 对应 route_key 已裁撤。

### 7.3 仍预留

1. `business.forward.generic`

## 8. Method 与 Route Key 映射

bootstrap 固定映射：

- `InitBootstrapChallenge` -> `auth.bootstrap.challenge`
- `AuthenticateBootstrap` -> `auth.bootstrap.authenticate`

新增最小通路映射：

- `VerifyToken` -> `auth.remote.verify.token`
- `ValidateSession` -> `auth.remote.validate.session`
- `ForwardUserPassword` -> `auth.external.forward.user_password`
- `ForwardBootstrapChallenge` -> `auth.external.forward.bootstrap.challenge`
- `ForwardBootstrapAuthenticate` -> `auth.external.forward.bootstrap.authenticate`

## 9. 模块职责基线

### 9.1 gateway

- 实现完整匹配优先级，已接入 bootstrap / remote_auth / external_auth 的最小路由与 client 适配。
- 外部输入内部目标字段必须忽略或拒绝。
- 输出完整 RouteProfile 核心字段。

### 9.2 certification_server

- 对认证相关 route_key 做权威处理，当前已覆盖 bootstrap + remote_auth + external_auth 的最小 RPC。
- 未识别 route_key 必须显式失败，不做宽松回退。
- 可保留 operation-centric 扩展字段，但不得破坏统一输入输出语义。

### 9.3 data_worker

- 至少支持 bootstrap_call、remote_auth_verify、external_auth_forward 出站映射到 certification_server。
- `business.forward.generic` 仍保留为后续阶段项。

## 10. 观测与审计最小字段

每次路由决策至少记录：

- route_key
- flow_category
- target_service_type
- target_service_name
- matched_by（route_key/static/hint）
- route_mapping_version
- request_id
- trace_id

## 11. 兼容与变更规则

1. 对已发布字段仅允许向后兼容扩展。
2. 破坏性改动需升级版本并同步更新本文件。
3. 方法名、route_key、核心语义任一变更，必须同步更新启动链说明与阶段时间线文档。

## 12. Proto 演进方向（后续开发基线）

### 12.1 拆分原则

1. 按业务域拆分 proto（bootstrap / remote_auth / external_auth / business_forward），而非按进程拆分。
2. 每个 proto 域可生成独立 client/server 接口，但不强制对应独立进程。
3. 单个服务进程可在同一 gRPC 端口注册多个 service；调用方可在同一连接上持有多个 stub。

### 12.2 拓扑约束

1. “多个 proto service”不等价于“多个 server 进程”。
2. 在当前阶段默认维持单进程多 service 注册，避免过早微服务化导致部署复杂度上升。
3. 只有在容量、隔离、发布节奏出现明确瓶颈时，才允许把 service 从单进程拆分到独立进程。

### 12.3 增量迁移路线

1. P0（已落地）：bootstrap 最小链路遵循统一字段语义，可通过结构化动态适配层接入。
2. P1（已落地）：固化 bootstrap proto 生成桩，gateway/data_worker 出站优先走真实 proto 调用。
3. P2（本轮推进中）：remote_auth / external_auth 的 proto service、gateway/data_worker 侧 client 适配与静态路由已完成最小闭环，相关业务逻辑保持最小实现。
4. P3：将动态调用路径降级为兼容路径，仅用于灰度与回滚。
5. P4：在兼容窗口结束后，收敛为“生成桩优先，动态通道按需保留”。

补充：本轮 P2 仅覆盖认证内部通路，`business.forward.generic` 仍是下一阶段主项。

### 12.4 开发与验收方向

1. 新增跨模块调用时，默认先定义 proto 再扩展 route_key，不再新增无 proto 约束的长期动态接口。
2. 每新增一个 rpc 方法，必须同步更新：
   - 本文件中的 route_key 映射与语义约定。
   - 启动链文档中的调用阶段与失败路径（如涉及启动期调用）。
   - 阶段时间线文档中的落地状态。
3. 本轮已落地的最小通路仅覆盖认证内部通道，下一轮优先补齐 `business.forward.generic` 与面向业务服务的目标映射，不再新增并行动态旁路。
4. 联调验收以“语义一致 + 路由可观测 + 失败可回溯”为硬性标准，不以“是否拆独立进程”作为验收前提。

## 13. 当前推进状态（2026-04-14）

1. 已完成：bootstrap、remote_auth、external_auth 的最小路由 / Proto 通路。
2. 进行中：`business.forward.generic` 与面向业务服务的目标映射。
3. 待办：编译与基础校验、后续回归测试。
