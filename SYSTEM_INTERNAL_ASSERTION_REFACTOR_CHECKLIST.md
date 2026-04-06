# 系统内部断言化改造流程清单（执行版）

版本：1.0.0  
状态：Archived（执行快照，仅供追溯）

说明：

- 本文档保留执行期清单形态，用于过程追溯。
- 当前运行期基线以 `SYSTEM_GLOBAL_BASELINE_DESIGN.md` 与 `SYSTEM_AUTH_STARTUP_CHAIN_DESIGN.md` 为准。
- 若与现行基线冲突，以现行基线文档为准。

## 1. 背景与目标

在星形流量拓扑前提下（外部流量 -> gateway -> 目标模块，普通模块之间无横向调用），将“运行期回认证中心校验”简化为：

- 网关执行主校验与主限流。
- 网关下发内部调用断言（签名）。
- 目标模块使用本地密钥管理能力做验签与轻量约束校验。
- 通道加密（commsec）保持现有机制，不在本次改造中弱化。

## 2. 范围与非范围

范围：

- Gateway -> Internal Service（优先 api_service）链路认证简化。
- 运行期内部请求的断言签发、传递、验签、重放防护。
- 内部限流由“可回源认证中心”调整为“消费网关断言后的身份上下文”。

非范围：

- 认证中心 bootstrap、令牌签发主流程改写。
- commsec 握手/密钥派生算法改写。
- 普通模块之间横向调用编排。

## 3. 前置门禁（必须先完成）

- [ ] 确认启动链路仍执行“bootstrap 就绪后再注册服务发现”。
- [ ] 明确网关私钥来源（本地私钥引用）与轮换策略。
- [ ] 明确目标模块可读全局公钥目录（按 key_id 与 entity_id 查询）。
- [ ] 确认网关到内部服务网络 ACL（拒绝非网关来源直连）。
- [ ] 统一内部头字段命名规范（当前存在 `-id` 与非 `-id` 混用）。

验收标准：

- [ ] 以上前置项均有配置或代码证据，可追溯到仓库文件。

## 4. 分阶段执行清单

## Phase 0：基线冻结与契约草案

目标：冻结当前行为，避免改造期间边界漂移。

任务：

- [ ] 建立内部断言契约草案（字段、签名算法、过期时间、重放策略）。
- [ ] 在 `SYSTEM_AUTH_STARTUP_CHAIN_DESIGN.md` 标注“运行期内部校验策略迁移中”。
- [ ] 形成网关和目标模块的头字段兼容映射表。

建议新增文件：

- `gateway/src/models/auth/internal_assertion.go`
- `api_service/src/models/auth/internal_assertion.py`

验收标准：

- [ ] 契约字段被冻结且评审通过。
- [ ] 兼容映射表可用于双栈过渡。

回滚点：

- 仅文档变更，可直接回退。

---

## Phase 1：Gateway 断言签发能力

目标：网关在转发时附带签名断言。

任务：

- [ ] 新增 `IInternalAssertionSigner` 接口。
- [ ] 使用本地私钥引用与 `CryptoUtils.SignByAlgorithm` 实现签名。
- [ ] 在 `grpc_forwarder` 注入断言元数据头（建议单头：`x-internal-assertion`）。
- [ ] 保留旧头（`x-downstream-*`）做过渡兼容，增加可配置开关。

建议改动文件：

- `gateway/src/interfaces/auth/`（新增 signer 接口）
- `gateway/src/services/auth/`（新增 signer 实现）
- `gateway/src/adapters/outbound/grpc_forwarder.go`
- `gateway/src/models/system/errors.go`（新增断言签发相关错误）

验收标准：

- [ ] 网关转发请求可携带可验签断言。
- [ ] 断言中包含目标服务、请求方法、路径、body 摘要、iat/exp/jti。
- [ ] 旧头与新断言可并行。

回滚点：

- 通过配置关闭断言头注入，继续使用旧头逻辑。

---

## Phase 2：目标模块本地验签与重放防护

目标：目标模块不回认证中心，改为本地验签。

任务：

- [ ] 新增 `IInternalAssertionVerifier`。
- [ ] 通过本地 `SecretKeyService` 按 `kid`/`gateway_id` 取公钥。
- [ ] 使用 `CryptoUtils.verify_by_algorithm/VerifyByAlgorithm` 验签。
- [ ] 校验 `aud/target_service`、`exp/iat`、`method/path/body_hash`。
- [ ] 引入 `jti` 重放防护（Redis TTL 窗口）。
- [ ] 产出已验证身份上下文供限流和业务层消费。

建议改动文件：

- `api_service/src/services/auth/`（新增 verifier）
- `api_service/src/adapters/grpc/server_adapter.py`（接入 unary interceptor）
- `api_service/src/usecase/ratelimit/enforce_inbound_uc.py`（优先使用已验证上下文）
- `api_service/src/models/sys/config.py`（断言验证开关与时钟偏差）

验收标准：

- [ ] 对篡改断言、过期断言、重放断言均拒绝。
- [ ] 对合法断言可构建稳定身份上下文。
- [ ] 在禁用回源模式下通过功能回归。

回滚点：

- 开关切回“旧头模式/回源模式”。

---

## Phase 3：内部限流策略切换

目标：把内部限流主体由“原始头字段”切到“验签后身份”。

任务：

- [ ] `DescriptorFactory` 输入从 headers 迁移到 verified identity。
- [ ] 统一 `session_id` / `token_id` 字段命名（去除 `x-downstream-session` 与 `x-downstream-session-id` 分裂）。
- [ ] 补充限流规则：优先 principal_id，其次 gateway_id+route。

建议改动文件：

- `api_service/src/usecase/ratelimit/enforce_inbound_uc.py`
- `gateway/src/interfaces/ratelimit/ratelimiter.go`（如需跨模块统一字段）
- `SYSTEM_GLOBAL_BASELINE_DESIGN.md`（限流凭据来源更新）

验收标准：

- [ ] 无认证中心回源情况下，限流准确率与旧模式等价或更优。
- [ ] 限流日志可回溯到断言 `jti/trace_id/principal_id`。

回滚点：

- descriptor 回退到旧 header 解析逻辑。

---

## Phase 4：去除运行期回源校验依赖（仅内部转发路径）

目标：内部转发请求不再触发认证中心运行期校验调用。

任务：

- [ ] 将 API Service 运行期 `validate/verify` 回源路径降级为可选（默认关闭）。
- [ ] 保留认证中心作为签发与目录权威，不参与每跳内部请求校验。
- [ ] 更新告警指标：断言验签失败率、重放命中率、回源调用量。

建议改动文件：

- `api_service/src/services/auth/session_svc.py`
- `api_service/src/services/auth/token_svc.py`
- 相关装配层（依赖注入）

验收标准：

- [ ] 内部转发请求回源调用量降为目标阈值（理想为 0）。
- [ ] 认证失败路径由本地验签逻辑统一返回。

回滚点：

- 历史记录：曾建议通过 `fallback_to_authority` 回切；该开关在当前基线中已移除，不再适用。

---

## Phase 5：文档收口与旧逻辑清理

目标：完成规范更新和兼容代码下线。

任务：

- [ ] 更新 `SYSTEM_AUTH_STARTUP_CHAIN_DESIGN.md`：明确“内部转发验签本地化”。
- [ ] 更新 `SYSTEM_GLOBAL_BASELINE_DESIGN.md`：补“内部断言机制”章节。
- [ ] 更新 `gateway/GATEWAY_DESIGN_SPEC.md`、`api_service/API_SERVICE_DESIGN_SPEC.md`。
- [ ] 删除旧头兼容与旧回源路径（确认灰度稳定后）。

验收标准：

- [ ] 设计文档与实现一致。
- [ ] 无死代码、无双路径分叉。

回滚点：

- 保留最近一个稳定 tag 的发布物。

## 5. 测试清单

单元测试：

- [ ] 断言签名/验签成功与失败路径。
- [ ] exp/iat 偏差容忍测试。
- [ ] body_hash 与 method/path 篡改测试。
- [ ] jti 重放检测测试。

集成测试：

- [ ] 网关合法转发 -> 目标模块放行。
- [ ] 非网关来源伪造头 -> 目标模块拒绝。
- [ ] key 轮换后新旧 key 兼容窗口行为。

压测与稳定性：

- [ ] 断言验签对 P95/P99 延迟影响。
- [ ] Redis 重放缓存容量与 TTL 策略验证。

## 6. 风险与控制

- 风险：仅依赖服务发现注册作为信任依据会被绕过。  
控制：必须启用来源网络控制 + 断言签名验证 + jti 重放防护。

- 风险：头字段命名不一致导致限流和审计偏差。  
控制：先统一契约，再切换主路径。

- 风险：时钟偏差引发误拒绝。  
控制：设置容忍窗口（例如 ±30s）并打点监控。

## 7. 发布与灰度建议

- [ ] 环境顺序：dev -> staging -> canary -> full。
- [ ] 灰度比例：5% -> 20% -> 50% -> 100%。
- [ ] 必看指标：验签失败率、重放命中率、5xx、P99。
- [ ] 回滚策略：配置开关优先，版本回滚兜底。

## 8. 完成定义（DoD）

- [ ] 内部转发链路默认使用断言本地验签。
- [ ] 目标模块内部请求不再依赖认证中心运行期校验。
- [ ] 通道加密复用能力保持不变。
- [ ] 文档、测试、监控三者全部同步完成。
