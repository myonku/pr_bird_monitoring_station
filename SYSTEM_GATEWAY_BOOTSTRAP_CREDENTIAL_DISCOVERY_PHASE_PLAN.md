# 网关 Bootstrap-凭证-服务发现闭环审查与阶段推进清单

版本：0.1.0  
状态：Review + Plan  
日期：2026-04-22  
范围：gateway（仅后端模块网关）

---

## 1. 目标与边界

本文档用于固化本阶段网关推进计划，目标是让网关在 auth 模式下形成完整闭环：

1. 启动后完成模块自身 bootstrap 并持有有效凭证（至少长期令牌）。
2. 仅在凭证有效时参与服务发现注册与续期。
3. 凭证失效后自动退出服务发现，并重新 bootstrap 后再恢复参与。
4. 全程遵循既定全局约束，不引入与现有架构冲突的实现。

本阶段明确不做：

1. 不新增“远程 revoke rpc 通道”。
2. 不改动认证中心权威边界（会话/令牌全局状态仍由 certification_server 负责）。
3. 不把凭证生命周期职责下沉到 AuthControl。

---

## 2. 约束基线（审查依据）

### 2.1 全局与链路约束

1. `SYSTEM_GLOBAL_BASELINE_DESIGN.md`
2. `SYSTEM_AUTH_STARTUP_CHAIN_DESIGN.md`
3. `SYSTEM_NO_AUTH_STARTUP_CHAIN_DESIGN.md`
4. `SYSTEM_BACKEND_LAYER_REFACTOR_DRAFT.md`
5. `gateway/GATEWAY_DESIGN_SPEC.md`

### 2.2 与本次目标直接相关的硬约束

1. 非认证中心模块必须负责本模块自身凭证生命周期。
2. Bootstrap 成功后必须写入 LocalCredentialManager（Redis 写入成功才算成功）。
3. AuthControl 不负责凭证状态管理，不调用 bootstrap。
4. no-auth 模式可短路认证链并不依赖凭证状态进行注册/续期。

---

## 3. 代码现状审查结论

## 3.1 已具备能力

1. 启动链已具备 no-auth 分支与 auth 分支入口，且 no-auth 可跳过 bootstrap。
2. LocalCredentialManager（Redis）基础能力已存在：保存/读取/过期标记/本地撤销。
3. RegistryService 已具备 etcd lease keepalive（注册后可自动续约心跳）。
4. 网关已具备 token refresh rpc client（`AuthAuthorityTokenRefreshService.RefreshTokenBundle`）。
5. 网关外部认证转发链（external auth）已基本连通。

## 3.2 关键缺口（按严重级别）

### P0-1：Bootstrap RPC 客户端仍是“最小握手 + 假签名”

现状：

1. 使用固定算法 `ed25519`。
2. 使用占位签名 `base64("bootstrap:"+challenge_id)`。
3. 未按认证中心验签口径构造真实签名载荷。

影响：

1. 在真实验签场景下，bootstrap 不具备可靠成功保证。
2. 算法与本地密钥类型不一致时将直接失败。

涉及实现：

1. `gateway/src/services/communication/rpc_client/auth_authority_bootstrap_rpc_client.go`
2. 对照口径：`certification_server/src/services/orchestration/orchestrator_bootstrap.go`

### P0-2：Bootstrap 结果结构被截断，无法支撑凭证状态管理

现状：

1. proto 响应有 `identity/session/tokens/issued_at/expires_at`。
2. 网关 handshake 结果仅保留 `stage + active_comm_key_id`。
3. 启动编排写入本地凭证时无法保存长期令牌与完整上下文。

影响：

1. 无法判定“是否持有有效长期令牌”。
2. 无法建立后续 refresh/re-bootstrap 状态机。

涉及实现：

1. `schemas/proto/auth/v1/auth_authority_bootstrap.proto`
2. `gateway/src/services/communication/rpc_client/auth_authority_bootstrap_rpc_client.go`
3. `gateway/src/services/orchestration/bootstrap_startup_orchestrator_svc.go`

### P0-3：服务发现参与与凭证状态解耦

现状：

1. 启动时 bootstrap 成功后立即注册。
2. 注册后续约由 etcd lease keepalive 常驻执行。
3. 运行期无凭证状态轮询、无凭证失效摘除、无自动 re-bootstrap 再注册。

影响：

1. 凭证失效时网关仍可能继续保活在服务发现中。
2. 与“只有持有有效长期令牌才能参与服务发现”的约束不一致。

涉及实现：

1. `gateway/src/app/lifecycle.go`
2. `gateway/src/services/common/registry_svc.go`
3. `gateway/src/services/common/local_credential_svc.go`

### P1-1：模块 refresh 能力未接入启动/运行编排

现状：

1. `TokenRefreshRPCClient` 已实现。
2. 启动链和运行链未消费该能力。

影响：

1. 本地凭证无法在长期令牌窗口内自动续期。
2. 发生 access 过期后缺少标准恢复路径。

涉及实现：

1. `gateway/src/services/communication/rpc_client/auth_authority_token_refresh_rpc_client.go`
2. `gateway/src/services/orchestration/bootstrap_startup_orchestrator_svc.go`
3. `gateway/src/app/lifecycle.go`

### P1-2：BootstrapCoordinator 只定义接口，未落地实现

现状：

1. 有 `IBootstrapCoordinator` 接口定义。
2. 无对应实现与生命周期接线。

影响：

1. 架构语义与代码事实不一致。
2. 后续扩展状态机时缺少稳定编排锚点。

涉及实现：

1. `gateway/src/iface/auth/bootstrap_coordinator.go`

### P2-1：测试覆盖缺口（缺少凭证-注册联动测试）

现状：

1. 当前测试集中在 `tests/http`、`tests/authcontrol`、`tests/common`、`tests/communication`。
2. 缺少 bootstrap 真签名、凭证状态机、注册摘除/恢复等测试。

影响：

1. 后续改造回归风险高。

---

## 4. 目标状态定义（本次改造完成标准）

在 auth 模式下，网关需满足以下行为：

1. 启动阶段：
   1.1 若本地无有效凭证，先 bootstrap。  
   1.2 bootstrap 成功且凭证落库成功后，才允许注册。  
2. 运行阶段：
   2.1 持续检测本地凭证状态。  
   2.2 仅在“持有有效长期令牌”时保持注册/续期。  
3. 失效恢复：
   3.1 凭证失效后主动退出服务发现（注销或停止续租）。  
   3.2 优先 refresh；refresh 不可用或失败时执行 re-bootstrap。  
   3.3 重新获取有效凭证后恢复注册。  
4. no-auth 模式：
   4.1 保持现有短路语义，不因凭证缺失阻塞注册/续期。  

“有效长期令牌”最小判定建议：

1. `stage == ready`。
2. `refresh_token_raw` 非空。
3. `refresh_expires_at > now`。
4. 凭证状态非 `revoked` / `expired`。

---

## 5. 分阶段推进清单

## 阶段 A：Bootstrap 契约补全（优先级 P0）

目标：让 gateway bootstrap rpc client 与 proto 完整对齐。

任务：

1. 将 bootstrap 请求模型从“最小字段”扩展为“完整请求视图”，至少包含：
   1.1 challenge request 的 client/gateway/source/request/trace。  
   1.2 runtime identity（与 proto 的 runtime 字段对齐）。
2. 将 bootstrap 响应模型扩展为完整结果，保留：
   2.1 stage。  
   2.2 identity/session/tokens。  
   2.3 active_comm_key_id、issued_at、expires_at。
3. 保留向后兼容：字段缺失时可降级处理，但不得丢弃已有字段。

建议改动文件：

1. `gateway/src/services/communication/rpc_client/auth_authority_bootstrap_rpc_client.go`
2. `gateway/src/models/auth/bootstrap.go`（如需补充模型）

验收标准：

1. Bootstrap client 能完整拿到并返回 proto 响应中的凭证状态字段。

## 阶段 B：真签名接入（优先级 P0）

目标：替换假签名，使用本地密钥真实签名 challenge。

任务：

1. 复用 `SecretKeyService.GetPublicKey/GetPrivateKeyRef` 获取本地材料。
2. 基于公钥检测签名算法（不在密钥目录固化算法字段）。
3. 按认证中心验签口径构造签名载荷（字段顺序与格式一致）。
4. 使用 `CryptoUtils.SignByAlgorithm` 生成签名。
5. 将签名算法与签名结果写入 bootstrap authenticate 请求。

建议改动文件：

1. `gateway/src/services/communication/rpc_client/auth_authority_bootstrap_rpc_client.go`
2. `gateway/src/services/orchestration/bootstrap_startup_orchestrator_svc.go`
3. `gateway/src/services/common/secret_key_svc.go`（仅在必要时补充导出能力）
4. `gateway/src/utils/crypto_utils.go`（若需补 helper）

验收标准：

1. development 模式下可通过认证中心真实验签完成 bootstrap。

## 阶段 C：本地凭证快照模型补全（优先级 P0）

目标：本地凭证数据能表达“长期令牌有效性”。

任务：

1. bootstrap 成功后保存以下关键数据到 LocalCredentialManager：
   1.1 principal/session/token family。  
   1.2 access/refresh token raw。  
   1.3 issued/expires（优先使用 refresh 相关时效作为长期凭证判定依据）。
2. 增加凭证状态元数据：
   2.1 credential_status。  
   2.2 refresh_expires_at_ms。  
   2.3 last_refresh_at_ms。  
   2.4 last_bootstrap_at_ms。
3. 提供统一判定函数：`IsCredentialValidForDiscovery`。

建议改动文件：

1. `gateway/src/services/orchestration/bootstrap_startup_orchestrator_svc.go`
2. `gateway/src/services/common/local_credential_svc.go`
3. `gateway/src/iface/common/local_credential_manager.go`（如需扩展接口）

验收标准：

1. 本地凭证可明确判断“是否持有有效长期令牌”。

## 阶段 D：凭证驱动的服务发现参与控制（优先级 P0）

目标：注册/续期必须受凭证状态约束。

任务：

1. 引入运行期 Supervisor（推荐独立服务），职责仅包括：
   1.1 定时检查本地凭证状态。  
   1.2 有效则确保注册/续期。  
   1.3 无效则触发注销或停止续租。  
2. 防抖与幂等：
   2.1 避免重复 register/unregister 抖动。  
   2.2 对失败重试引入退避。
3. no-auth 分支保持当前行为：不受凭证约束。

建议改动文件：

1. `gateway/src/app/lifecycle.go`
2. `gateway/src/services/common/registry_svc.go`（必要时补状态检查辅助）
3. `gateway/src/services/orchestration/`（新增 supervisor）

验收标准：

1. 凭证失效后，网关不会继续保持可发现状态。
2. 凭证恢复后，网关可自动恢复注册。

## 阶段 E：refresh / re-bootstrap 闭环（优先级 P1）

目标：形成运行期自恢复。

任务：

1. 先 refresh，后 re-bootstrap：
   1.1 refresh token 仍有效时优先走 refresh。  
   1.2 refresh 失败且不可恢复时走 re-bootstrap。  
2. refresh 成功后更新本地快照并维持注册。
3. re-bootstrap 成功后覆盖本地快照并恢复注册。
4. revoke 继续保留本地撤销语义（不新增远程 revoke rpc）。

建议改动文件：

1. `gateway/src/services/communication/rpc_client/auth_authority_token_refresh_rpc_client.go`
2. `gateway/src/services/orchestration/`（supervisor 或协调器）
3. `gateway/src/services/common/local_credential_svc.go`

验收标准：

1. 运行期 token 轮换后可无人工干预保持服务发现可用。

## 阶段 F：观测与测试补齐（优先级 P1/P2）

目标：可回归、可排障。

任务：

1. 增加阶段日志：
   1.1 credential_probe。  
   1.2 credential_refresh_attempt/success/fail。  
   1.3 credential_invalid_unregister。  
   1.4 credential_rebootstrap_success/fail。  
2. 增加测试：
   2.1 bootstrap rpc client 请求/响应映射测试。  
   2.2 真签名 payload 口径测试。  
   2.3 凭证状态机与注册联动测试。  
   2.4 no-auth 跳过测试。  

建议新增测试目录：

1. `gateway/tests/orchestration/`
2. `gateway/tests/communication/rpc_client/`
3. `gateway/tests/app/`

验收标准：

1. `go test ./...` 覆盖新链路并稳定通过。

---

## 6. 任务依赖关系与推荐顺序

1. A -> B -> C -> D -> E -> F。
2. 原因：
   2.1 无完整 bootstrap 契约与真签名，无法获得可信凭证。  
   2.2 无完整本地快照，无法做状态驱动注册。  
   2.3 无状态驱动注册，无法达成“仅凭证有效时参与服务发现”。

---

## 7. 风险与缓解

1. 风险：签名口径不一致导致 bootstrap 全失败。  
   缓解：先加 payload 构造单测，对齐认证中心字段顺序和格式。
2. 风险：状态机抖动导致频繁注册/注销。  
   缓解：增加最小稳定窗口与指数退避。
3. 风险：Redis 异常导致凭证状态不可读。  
   缓解：按约束直接判定不可参与服务发现并记录告警日志。
4. 风险：refresh 与 re-bootstrap 并发竞争。  
   缓解：Supervisor 内部串行化状态迁移，保证单活流程。

---

## 8. 阶段交付物清单

1. 代码：A-F 阶段对应改造。
2. 文档：更新 gateway 设计文档相关章节与本文件版本。
3. 测试：新增并通过对应用例。
4. 验收记录：
   4.1 auth 模式：可完成 bootstrap -> 注册 -> refresh/re-bootstrap -> 注册恢复。  
   4.2 no-auth 模式：可直接注册/续期且不触发认证链。

---

## 9. 本阶段结论

当前网关已具备“基础启动 + 基础注册 + 外部认证转发”框架，但尚未达到“凭证状态驱动服务发现参与”的目标态。  
建议按本清单分阶段推进，其中 A-D 为必须优先完成项；E-F 为稳定性和可运维能力补齐项。
