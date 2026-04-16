# 后端模块推进记录与时间线基准

版本：1.2.0
状态：Baseline-Timeline
适用范围：gateway / certification_server / data_worker

## 1. 文档目的

本文件作为后端模块推进记录与时间线基准，用于：

- 固化本阶段在全局约束下的实际推进结果。
- 记录阶段计划与阶段问题的精简结论，避免后续重复回溯。
- 给出下一步可直接推进的工作清单。
- 作为后续阶段更新的统一时间线入口。

说明：

- 本文件不替代模块内设计文档。
- 本文件不定义新的协议语义，只记录阶段状态与执行基线。

## 2. 约束来源（必须同时满足）

后续推进默认继承以下约束：

1. 全局统一约束：`SYSTEM_GLOBAL_BASELINE_DESIGN.md`
2. 后端层级重构方向：`SYSTEM_BACKEND_LAYER_REFACTOR_DRAFT.md`
3. 认证与 development 启动链：`SYSTEM_AUTH_STARTUP_CHAIN_DESIGN.md`
4. no-auth 启动链对照：`SYSTEM_NO_AUTH_STARTUP_CHAIN_DESIGN.md`
5. 路由与 proto 基准约定：`SYSTEM_BACKEND_ROUTE_PROTO_BASELINE.md`

## 3. 阶段目标与当前达成

本阶段主目标：

- 在不展开完整业务链路前，先打通后端模块“启动 -> 注册 -> 最小运行态”主链路。

当前达成（截至 2026-04-14）：

1. 三模块（gateway/certification_server/data_worker）已形成统一的启动主链结构，bootstrap 就绪、注册与最小运行态基线保持有效。
2. gateway 与 data_worker 已具备 bootstrap 就绪链路，并已按路由 / Proto 基线补齐 remote_auth / external_auth 的最小内部通路；下游授权与目标侧复核已在本阶段裁撤。
3. certification_server 已注册 bootstrap、remote_auth、external_auth 三类 gRPC 服务，认证编排层补入用户凭证返回契约。
4. 用户凭证验证结果现可返回最小身份快照，支持会话与令牌组装，但仍保持业务逻辑最小实现。
5. 服务发现注册路径、最小实例字段、失败回退与阶段日志保持可执行基线。
6. bootstrap 及内部认证通路的 route_key 与方法映射已完成收敛。
7. 路由匹配优先级与未知规则失败语义已完成本阶段收敛。
8. 目前仍有两项推进差距需要后续补齐：gateway 的对外启动链路与运行态接线尚未闭环，data_worker 的顶层编排与实际调用接线也仍停留在骨架/预留层。

## 4. 时间线（精简记录）

### 2026-04-09

- 启动链收敛方向确定为“先闭环启动与注册，再展开业务链路”。
- 后端层级重构草案推进到 0.7.0，固定统一流量站点、通信下层分路、凭证管理边界与协议角色。

### 2026-04-10（第一轮验收）

- 路由/Proto/注册链细则完成冻结化整理。
- 验收识别 4 项实现偏离（route_key、匹配优先级、未知规则失败、hint 信任边界）。
- 识别 3 项表述冲突，其中 2 项确认为有意策略（不整改）。

### 2026-04-10（修复与复验）

- 4 项实现偏离均完成修复。
- 待裁决冲突项（认证中心路由契约同构性）随实现对齐已消解。
- 二轮复验通过：Go 模块可编译运行，Python 模块语法编译通过。

### 2026-04-13（当前审阅补充）

- 全局文档已同步收口：SYSTEM_GLOBAL_BASELINE_DESIGN、SYSTEM_AUTH_STARTUP_CHAIN_DESIGN、SYSTEM_NO_AUTH_STARTUP_CHAIN_DESIGN、SYSTEM_BACKEND_LAYER_REFACTOR_DRAFT、SYSTEM_BACKEND_ROUTE_PROTO_BASELINE 与当前主线对齐，握手/加密通道阶段表述已抽离。
- gateway 的 FlowCategoryBusinessForward 映射策略仍处于待定状态，本文件仅记录问题，不展开具体路由映射方案。
- 路由与认证回源链路已作为当前主线继续推进，安全链路闭合不再作为阶段目标。

### 2026-04-14（内部通道最小推进）

- certification_server 当时新增 remote_auth / external_auth / target_reverify 三类 RPC 服务注册（现已裁撤 target_reverify），bootstrap 之外的内部认证通路进入最小闭环。
- external_auth 已补入外部 bootstrap 转发（ForwardBootstrapChallenge / ForwardBootstrapAuthenticate），并明确与 gateway 启动期 bootstrap_call 解耦；本次修补仅涉及 gateway 与 certification_server。
- IUserCredentialManager 返回契约收敛为最小身份快照，ValidateCredentials 不再是空声明，编排层可以继续组装 session / token。
- gateway / data_worker 侧补齐对应 route_key 静态映射与 client 适配，占位调用链已能对接认证中心新 RPC。
- business.forward.generic 仍未展开，下一轮优先补齐面向业务服务的转发链路与目标映射。
- 编译与基础校验仍待执行，作为本轮收口动作。

### 2026-04-15（阶段诊断补充）

- 当前现状：gateway 与 data_worker 都已经具备部分认证路由、proto 和 client/adapter 骨架，但启动链路与运行态接线尚未完成，距离“可直接承载业务”的完整主链仍有差距。
- 当前现状：certification_server 的 external_auth / bootstrap / remote_auth / target_reverify（当时状态，现已裁撤）已按当时基线接入，external bootstrap 复用共享 bootstrap 处理器的方向正确，暂不需要再拆分新的 bootstrap 逻辑。
- 当前现状：关于认证中心和no-auth 模式的说明：暂时在该模式下将认证中心视为透明，本轮不调整其处理语义；若后续直接选择 no-auth 下不启动认证中心，也无需为其单独补改认证链路。
- 当前现状：SessionInfo 与 Session 的冲突已不再存在，当前代码与 proto 语义已经统一到 Session，剩余的是少量旧注释、骨架接口名和文档表述需要收尾。
- 后续方向：优先补全 gateway 的启动链路与对外接入，再补全 data_worker 的顶层编排与真实调用链接线。
- 后续方向：继续保持 external_auth_forward 等既定通道约定；target_reverify_call 已裁撤，不再额外引入并行认证旁路。
- 后续方向：统一更新过时注释、接口说明和阶段文档中的旧命名，减少 Session / external_auth / route 分类的语义漂移。

### 2026-04-16（设计裁剪与文档同步）

- 本轮已将 target_reverify 与 downstream grant 相关设计从代码、proto、接口层和生成物中移除，并同步补齐文档收口。
- 当前后端现行基线仅保留 bootstrap、remote_auth、external_auth 与 business_forward 主线；目标侧二次复核不再作为独立设计项。
- 阶段记录已更新为当前状态说明，旧的 2026-04-14~2026-04-15 记录仅作为历史快照保留。

## 5. 阶段问题精简结论（来自已归档问题单）

### 5.1 已关闭问题

1. bootstrap route_key 未按冻结值落地：已关闭。
2. 匹配优先级未按冻结顺序：已关闭。
3. certification_server 未对未知 route_key 显式失败：已关闭。
4. target_service_hint 缺少可信边界：已关闭。
5. IUserCredentialManager 返回契约仍为空声明：已关闭，已收敛为最小身份快照返回。
6. 修复认证中心重复抽象问题，收敛 IAuthGatewayChannel 与 IAuthRequestOrchestrator 的职责边界：已完成。

## 6. 临时整改清单（不含网关路由映射方案）

1. 将 gateway 的业务流量映射策略保持为待定事项，暂不在本文件内展开 route mapping 设计方案。
2. 继续沿现有启动主链推进后端最小运行态，不把尚未推进到的额外安全准备与 gRPC 端口接线纳入当前问题单。
3. 保持启动、注册、阶段日志、回退注销等基线不变，作为后续业务闭环的共同前提。
4. 认证内部通道的最小 RPC 已完成，后续问题单仅继续跟踪 business.forward.generic 与验收补强。

## 7. 下一步可推进项

### 7.1 路由与认证链扩展

1. 将 `business.forward.generic` 按相同规则逐步落地，并补齐面向业务服务的目标映射与调用链。
2. 将已落地的 remote_auth / external_auth 通路保持为稳定约定，不再新增并行动态旁路。

### 7.2 认证与模式治理

1. 在 development 模式继续收敛业务通路与双端认证复核流程。
2. 明确 no-auth 下的降级边界与恢复切换策略，补全演练说明。

### 7.3 可观测与验收自动化

1. 将启动阶段日志最小集固化为自动验收断言。
2. 为注册失败、启动失败、注销回退以及新补齐的认证内部通路补充回归测试用例。
3. 运行编译与基础校验，确保本轮最小通路可落地。
4. 对 route mapping version、matched_by、trace/request 形成统一审计采样。

### 7.4 本次诊断后的补充推进项

1. gateway 先补全启动链路与运行态接线，作为当前优先级最高的追赶项。
2. data_worker 按同样标准补全启动链路与运行态接线，避免只停留在路由/适配骨架。
3. no-auth 模式本轮暂不变更，按“认证中心透明、可直接不启动认证中心”的现状处理。
4. 后续统一整理注释与接口说明，清理已过时的骨架命名和旧语义描述。

## 8. 后续维护规则（时间线更新规则）

后续每次阶段推进按以下格式追加更新：

1. 日期（YYYY-MM-DD）
2. 本次范围（改动边界）
3. 完成项（最多 5 条）
4. 风险/阻塞（最多 3 条）
5. 下一步（最多 3 条）

禁止在本文件中记录模块内部实现细枝末节；模块级细节仍归属各模块文档与代码。
