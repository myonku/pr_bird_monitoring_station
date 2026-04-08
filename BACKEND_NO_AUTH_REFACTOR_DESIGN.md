# 后端模块结构改造说明（简化 + no-auth）

版本：1.0.0  
状态：Draft

## 1. 文档目的

本说明用于指导后端模块的结构改造，目标是：

- 在不改动系统级理念的前提下，简化后端实现结构。
- 引入并统一落地 `no-auth` 运行模式。
- 保证后续开发与现有设计文档一致，避免实现跑偏。

本说明不新增系统级原则，仅将现有全局约束映射为可执行的模块改造方案。

---

## 2. 适用范围与边界

适用模块：

- gateway
- api_service
- certification_server
- data_worker

不在本次改造范围内：

- edge_server 的边缘侧工作流细节
- 客户端认证流程
- 全局规范本身（ID、密钥、信任边界、网关路由决策边界）

---

## 3. 对齐基线（必须遵守）

本次改造以以下文档为上位约束：

- `SYSTEM_GLOBAL_BASELINE_DESIGN.md`
- `SYSTEM_AUTH_STARTUP_CHAIN_DESIGN.md`
- `SYSTEM_NO_AUTH_STARTUP_CHAIN_DESIGN.md`

对齐要点：

1. 外部请求目标服务映射仍由 Gateway 路由配置统一决策。
2. 后端模块必须支持 `no-auth`，且仅用于开发联调。
3. 非 `no-auth` 模式下，后端模块间通信仍遵守握手与加密约束。
4. 目标模块对网关注入的下游认证上下文仍执行回源认证校验（非 `no-auth`）。

---

## 4. 改造目标

### 4.1 结构简化目标

- 将“认证调用 + 限流决策”在调用编排层整合为统一入口（认证控制模块）。
- 将通道语义收敛为两类逻辑通道：
  - 认证调用通道（Authority Channel）
  - 业务转发通道（Business Channel）
- 保持统一转发结构，避免并行维护双套通信栈。

### 4.2 no-auth 目标

- 通过装配层开关禁用认证与限流，不在业务流程散落条件分支。
- 业务链路在 `no-auth` 下可持续运行（转发、处理、任务执行）。
- 与 development 模式共享主干代码路径，减少测试矩阵裂变。

---

## 5. 目标结构总览

### 5.1 认证控制模块（AuthControl）

定义：

- 认证控制模块是“编排门面”，不是将认证与限流的领域模型硬合并。

职责：

- 认证相关：bootstrap 就绪、session/token 校验、downstream grant、模块凭证续期。
- 限流相关：基于 verified identity 生成描述符并执行限流决策。
- 模式相关：根据 mode 决定是否短路认证与限流。

收益：

- 调用点单一，减少重复编排。
- no-auth 开关集中，避免散点判断。

### 5.2 双通道逻辑（非双实现）

统一要求：

- 保留一套通信数据结构与一套转发实现。
- 通过通道策略（profile）区分行为，不拆第二套无加密协议栈。

通道策略：

1. Authority Channel（认证调用通道）
  - development：强制握手 + 强制加密。
  - no-auth：直接不启用（请求不应进入远程认证调用）。

2. Business Channel（业务通道）
  - development：支持握手与加密（默认启用）。
  - no-auth：允许关闭握手与加密，但保留统一上下文结构。

### 5.3 业务通道信任凭证承载

要求：

- 业务通道需支持承载网关下发的信任凭证对象。
- 在关闭应用层加密时，仍可携带可校验的信任元数据（最小化裸头信任风险）。

建议最小字段：

- principal_id
- session_id
- token_id
- gateway_id
- source_service
- target_service
- issued_at / expires_at
- verify_mode
- mode（development/no-auth）

---

## 6. 模块级改造说明

## 6.1 Gateway

现状摘要：

- 存在安全准备链路（grant + EnsureChannel + 可选加密）。
- 认证与通道准备在多个层次有重复编排。

改造动作：

1. 新增 `AuthControlCoordinator`（或同等门面）供入站与转发复用。
2. 将出站安全准备收敛为单一实现，去除重复链路。
3. 引入 `runtime.mode` 与通道策略：
  - `development`: 完整认证 + 限流 + 通道握手加密
  - `no-auth`: 认证短路 + 限流关闭 + 业务通道可明文
4. 保持现有路由决策边界不变（仍由 Gateway 配置决定目标服务）。

不变项：

- 外部请求不能指定内部目标服务标签作为强制路由输入。
- 对内转发上下文字段命名与语义保持与现有文档一致。

## 6.2 API Service

现状摘要：

- 入站回源认证校验与限流决策逻辑接近，但仍分离在不同组件。

改造动作：

1. 在 gRPC 入站链引入统一认证控制拦截器（先校验身份，再限流决策）。
2. 限流主体继续以 verified identity 为主输入。
3. `no-auth` 模式下：
  - 不装配回源认证拦截器。
  - 不装配限流拦截器。
  - 仅保留最小业务处理链路。

不变项：

- 默认不启用横向调用编排能力。
- 检测到横向调用请求头时仍拒绝。

## 6.3 Certification Server

现状摘要：

- auth 与 commsec 服务实现已存在，但对外适配层仍需更清晰分面。

改造动作：

1. 对外接口分面清晰化：
  - 认证调用面（challenge/bootstrap/verify/refresh/grant）
  - 通道安全面（handshake/channel/encrypt/decrypt）
2. 在装配层支持 `no-auth`：
  - 认证签发主链关闭。
  - 限流链关闭。
  - 通道握手与加解密链关闭。
  - 保留最小健康能力或按部署策略不启用本模块。

不变项：

- 认证中心仍是认证权威与公钥目录权威。

## 6.4 Data Worker

现状摘要：

- 当前仍为骨架实现。

改造动作：

1. 先补齐与其他模块一致的 `runtime.mode` 配置语义。
2. development/no-auth 的行为切换遵循统一策略：
  - development：可接认证/限流/通道策略。
  - no-auth：最小任务处理链路，不依赖认证中心。

---

## 7. 配置与装配改造

### 7.1 统一配置键

为四个后端模块统一新增：

- `[runtime] mode = "development" | "no-auth"`

默认值建议：

- development（保持现有行为兼容）

### 7.2 装配层策略注入

通过依赖注入切换真实实现与 Noop 实现：

- AuthAuthorityClient: real / noop
- RateLimiter: real / allow-all
- CommSecCoordinator: real / bypass

约束：

- 业务代码不直接判断 mode。
- mode 判断仅在启动装配层完成。

---

## 8. 分阶段实施计划

Phase 0：基线冻结

- 固化现有接口与文档版本。
- 建立“非目标清单”（禁止改全局规范）。

Phase 1：接口收敛（兼容期）

- 引入 AuthControl 门面接口。
- 引入通道 profile 与 mode 配置结构。
- 保留旧接口适配，确保编译与启动不回归。

Phase 2：Gateway 先行

- 收敛安全准备链路。
- 接入 AuthControl 门面。
- 打通 `no-auth` 转发最小链路。

Phase 3：API Service 对齐

- 拦截器链接入 AuthControl。
- 严格保证 verified identity-first 的限流输入。
- 打通 `no-auth` 最小业务处理。

Phase 4：Certification Server 分面与策略

- 完成 auth/commsec 对外面分离。
- 落地 `no-auth` 下的最小壳行为。

Phase 5：Data Worker 补齐 + 联调验收

- 补齐 mode 装配。
- 执行跨模块联调矩阵。

---

## 9. 验收清单（防偏移）

满足以下条件视为改造达成：

1. 系统级理念未改动（路由边界、信任边界、全局约束保持不变）。
2. 后端四模块均可识别 `runtime.mode` 并切换到 `no-auth`。
3. Gateway、API Service 在 `no-auth` 下可完成最小业务链路。
4. development 下认证与限流能力保持可用。
5. 通道能力保持统一实现，不存在并行双栈分叉。
6. 认证调用通道与业务通道策略可独立配置。

---

## 10. 风险与回滚

主要风险：

- 兼容期接口过多导致调用链重复。
- mode 开关落在业务层导致行为漂移。
- 通道策略切换不彻底引发隐式明文。

回滚策略：

1. 分阶段发布，每阶段保留旧接口适配层。
2. 每阶段均可回滚到 development-only 装配。
3. 关键开关（mode/profile）保留启动参数覆盖能力。

---

## 11. 后续执行建议（按优先级）

1. 先改 Gateway（影响面最大，且是路由与转发入口）。
2. 再改 API Service（入站链路短，验证快）。
3. 再改 Certification Server（分面清晰后统一全局对接）。
4. 最后补 Data Worker（骨架模块，成本低）。
