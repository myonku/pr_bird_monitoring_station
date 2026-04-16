# 认证中心推进动工清单（以全局设计为准）

版本：1.0.1
日期：2026-04-16
状态：Working Checklist

## 0. 使用说明

- 本清单以 `SYSTEM_GLOBAL_BASELINE_DESIGN.md`、`SYSTEM_BACKEND_ROUTE_PROTO_BASELINE.md`、`SYSTEM_BACKEND_PROGRESS_TIMELINE.md` 为唯一优先基线。
- `certification_server/CERTIFICATION_SERVER_DESIGN_SPEC.md` 仅作为认证中心本模块的骨架参考；如果与全局设计冲突，以全局设计为准。
- 本清单的目标不是重复设计，而是把当前实现与后续收口工作拆成可以直接执行的推进项。

## 1. 当前已确认的落地边界

- [X] certification_server 已具备 `bootstrap`、`remote_auth`、`external_auth`、`token_refresh` 四类 gRPC 权威入口。
- [X] `token_refresh` 已冻结为独立 route/proto/service 通路，gateway 外部转发与认证中心模块自刷新都已同步对齐。
- [X] `target_reverify` 与 `downstream grant` 已裁撤，不再作为当前基线。
- [X] 入站链已收敛为 `gRPC handler -> Traffic Station -> Routing/Payload Pipeline -> Orchestrator -> Capability Modules -> Managers -> Repo/Storage`。
- [X] 全局文档已同步 refresh 语义，旧 grant 表述已从全局主线中清理。
- [X] no-auth 模式下认证中心默认不启动；若进程被拉起，应在判定 run_mode=no-auth 后自主停止，作为当前暂时性设计方向。
- [X] 认证中心只负责全局 bootstrap / 用户密码认证阶段的凭证签发、全局凭证管理，以及对 gateway 的远程认证调用作出权威响应；不承担自身 bootstrap 流程，也不发起自身认证调用。
- [X] bootstrap 与用户名密码认证成功后，认证中心返回统一凭证结果结构；当前实现以 TokenBundle 作为核心令牌子集，必要时可附加身份、会话和时间信息，不按模块区分凭证容器。
- [X] 认证中心自身凭证不纳入当前设计边界，本轮不讨论自签发、自持有或自管理。

## 2. P0：先做的收口项

### 2.1 启动装配闭环

- [X] 完成 `certification_server/main.go` 与 `src/app/lifecycle.go` 的单入口启动链，固定配置、仓储、管理器、编排层、gRPC 注册、退出回收的顺序。
- [X] 完成 bootstrap 权威能力的输入输出约束收口。
  - 验收：challenge 构造、签名验签、会话签发、令牌签发与全局基线一致；不使用模块本地特例语义。
- [X] commsec 通道设计已废弃，相关骨架约束从当前推进范围移除。
  - 说明：不再推进独立通道管理骨架，通道生命周期不作为当前认证中心的独立能力边界。
  - 验收：支持 username/email/phone 识别；密码错误、用户不存在、风控拒绝、禁用状态可区分；不回显敏感信息。
- [X] 收敛用户凭证到最小身份快照的返回格式，保证 `HandleUserPasswordAuth` 只消费认证结果，不承担用户管理职责。
  - 验收：编排层只接收 principal/role/scopes 级别结果；审计字段保留 request_id、trace_id、fingerprint。


- [X] 保持 `rpc_mapping.go`、`lifecycle.go` 与生成代码同步。
  - 验收：新增 service / method 时必须同步注册、映射与生成物，不允许只改一处。
- [X] 收口 `src/services/communication/traffic_station_svc.go` 与 `src/services/communication/routing_payload_pipeline_svc.go` 对 bootstrap / remote_auth / external_auth / token_refresh 的分类、策略、静态路径映射。
  - 验收：route_key、flow_category、target_service_type、target_service_name 完整一致；未知 route 必须显式失败；外部 hint 不得影响可信决策。
- [X] 校验 `AuthAuthorityTokenRefreshService.RefreshTokenBundle` 与 `AuthAuthorityExternalAuthService.ForwardRefreshTokenBundle` 的路由、头部、元数据字段一致。
  - 验收：refresh 续期在 gateway 外部转发与认证中心内部自刷新两条链路上语义一致，审计字段一致。

## 3. P1：认证中心完工条件

### 3.1 数据管理器

- [X] 完成 `src/iface/common/key_manager.go` 与 `src/services/common/secret_key_svc.go` 的单活公钥目录语义。
  - 验收：按 `key_id`、`entity_id`、owner 维度都能查到当前激活公钥；不再依赖算法字段做目录过滤；双活约束有效。
- [X] 完成 `src/iface/common/registry_manager.go` 与 `src/services/common/registry_svc.go` 的注册、查询、心跳、失活与回退策略。
  - 验收：实例注册键、心跳刷新、查询筛选、失败回退行为可复现；不把服务发现当作身份可信证明。
- [X] 完成 `src/iface/common/session_manager.go` 与 `src/services/common/session_svc.go` 的会话生命周期收口。
  - 验收：创建、查询、Touch、Validate、Revoke 语义一致；Redis / 内存回退和过期策略固定；会话状态字段可用于后续认证判断。
- [X] 完成 `src/iface/common/token_manager.go` 与 `src/services/common/token_svc.go` 的令牌生命周期收口。
  - 验收：Issue / Bundle / Refresh / Verify / Revoke / RevokeFamily 语义完整；refresh 旋转后旧 refresh 失活；family 与 session 的联动正确。

### 3.2 能力模块

- [X] 完成 `src/iface/authcontrol` 下入站限流与认证决策消费的最终边界。
  - 验收：AuthControl 只做入站校验与限流决策，不调用 Bootstrap；错误码与全局 errors 保持一致。
- [X] 完成 bootstrap 权威能力的输入输出约束收口。
  - 验收：challenge 构造、签名验签、会话签发、令牌签发与全局基线一致；不使用模块本地特例语义。
- [X] commsec 通道设计已废弃，相关骨架约束从当前推进范围移除。
  - 说明：不再推进独立通道管理骨架，通道生命周期不作为当前认证中心的独立能力边界。

### 3.3 通信服务

- [X] 完成 `src/services/communication/auth_authority_bootstrap_rpc_svc.go`、`auth_authority_remote_auth_rpc_svc.go`、`auth_authority_external_auth_rpc_svc.go`、`auth_authority_token_refresh_rpc_svc.go` 的错误映射、审计字段、空值保护统一。
  - 验收：所有权威 RPC 的错误前缀、状态码、payload 组装方式一致；不会出现一条链路的字段口径与其它链路分裂。
- [X] 保持 `rpc_mapping.go`、`lifecycle.go` 与生成代码同步。
  - 验收：新增 service / method 时必须同步注册、映射与生成物，不允许只改一处。

## 4. P2：交付前验收

- [X] 为 `auth_request_orchestrator_svc.go`、`user_credential_svc.go`、`token_svc.go`、`session_svc.go`、`secret_key_svc.go` 补齐最小单元测试。
  - 验收：覆盖成功、缺参、过期、失活、找不到、依赖缺失、错误码映射。
- [X] 补齐认证中心的集成烟雾测试，至少覆盖 bootstrap、用户名密码、token refresh、session validate 四条主路径。
  - 验收：从 handler 到 manager 的主链路可在单机环境跑通。

## 5. 明确不回退的约束

- [ ] 不恢复 `target_reverify`。
- [ ] 不恢复 `downstream grant` 作为当前基线能力。
- [ ] 不把模块分文档当作全局事实来源。
- [ ] 不把外部请求的 target hint 当作可信内部目标。
- [ ] 不把 transport / 连接实现细节写回全局设计约束。

## 6. 推荐推进顺序

1. 先补用户凭证真实化，关闭 `user_credential_svc` 的最小实现缺口。
2. 再把编排层接通到 session / token / key / registry 等管理器。
3. 再收口 traffic station 与 routing/payload pipeline 的一致性。
4. 再统一错误模型、日志、审计与限流边界。
5. 最后补测试、编译验证和阶段时间线记录。
