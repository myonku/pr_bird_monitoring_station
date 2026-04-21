# 系统全局基线设计说明（统一约定）

版本：1.2.2
状态：Baseline

## 1. 文档目的

本说明作为工作区级全局规范，统一以下内容：

- 跨模块统一约定（ID 规范、密钥规范、配置规范、初始化约定）。
- 模块间职责边界和实现前置约束。
- 外部请求目标服务决策边界与 no-auth 运行模式基线。

说明：

- 各模块内设计文档仅保留层级/结构/接口等架构信息。
- 全局统一约定以本文件为唯一基准。
- 按模块认证链路与启动链路见 `SYSTEM_AUTH_STARTUP_CHAIN_DESIGN.md`。
- 边缘端认证与上传通信协议细节已统一收敛到 `SYSTEM_EXTERNAL_INTERFACE_CATALOG_DESIGN.md`。

---

## 2. 适用范围

适用于以下模块：

- gateway
- certification_server
- edge_server
- data_worker

不适用于：

- 客户端本地密钥 bootstrap（客户端不采用该模式）。
- model_trainer（训练侧不参与系统运行流程）

---

## 3. 全局唯一标识规范（强制）

### 3.1 UUID 版本要求

整个系统内实体 ID 与其他唯一性标识符统一使用 UUID v4 字符串表示。

### 3.2 字段适用范围

以下字段（含语义等价字段）必须为 UUID v4：

- entity_id
- user_id
- device_id
- service_id
- gateway_id
- module_id
- session_id
- token_id
- token_family_id / family_id
- request_id
- trace_id
- event_id
- challenge_id
- key_id

### 3.3 兼容与迁移约束

- 历史文档中非 UUID 的示例值仅作占位示意，不作为实现基准。
- 新增模型字段、接口字段、配置字段时，若语义为“全局唯一标识”，默认使用 UUID v4。

---

## 4. 本地密钥存储规范（强制）

适用对象：除客户端之外的系统模块（gateway、edge_server、data_worker 等）。

统一要求：

- 本地仅允许存在一对当前生效密钥（单活）。
- 私钥格式固定为 PKCS#8 PEM。
- 公钥格式固定为 SPKI PEM。
- 密钥轮换时必须先切换新单活密钥，再安全退役旧密钥。
- 本地密钥对文件名固定为 `public.pem` / `private.pem`，路径由配置中的 `secret_key_dir` 指定；密钥管理类只负责加载本地密钥对和按 ID 查询公钥，不把文件名与 `key_id` 绑定，也不以 `active_key_id` 作为启动门槛。

边界说明：

- 认证中心同样持有本模块本地单活密钥对，用于本模块自身认证与签名相关场景；但认证中心不通过 bootstrap 获取自身密钥对。
- 认证中心不持有业务模块私钥原文，仅校验公钥目录与签名结果。
- 客户端不参与本地密钥 bootstrap。

公钥目录约束：

- 系统内所有需要记录公钥的非客户端实体（service/device/gateway/worker 等）统一使用同一张公钥目录表结构，不按模块拆分多套结构。
- 公钥查询必须收敛为统一目录查询请求（等价 `LookupPublicKey` 语义），至少支持三种检索条件：
  - 按 `key_id` 精确查询。
  - 按 `entity_id` 查询当前可用公钥（用于 `key_id` 缺失或不确定场景）。
  - 按 owner 维度查询（`entity_type + entity_id + instance_id`）。
- 查询请求必须支持 `require_active` 等价语义，要求仅返回当前激活密钥。
- 模块配置文件至少应包含一个可用的 bootstrap 查钥提示：`active_key_id` 优先，缺失时允许直接使用 `entity_id`（后端 `instance_id`，边缘端 `device_id`）参与 bootstrap；只要 `key_id` 或 `entity_id` 中至少一个存在即可启动，认证中心必须同时支持二者查询公钥。

### 4.1 公钥目录语义收敛（强制）

- owner 语义统一使用 entity 维度：`entity_type`、`entity_id`、`instance_id`（可选）。
- 禁止新增或继续依赖 `owner_type` 作为并行语义轴，避免与 `entity_type` 重复。
- 公钥目录表与密钥领域模型必须保持同构语义，不得出现 service/entity 双轨字段并存。

### 4.2 密钥模型边界（强制）

- 密钥实体模型仅承载 key material 与归属关系（如 `key_id`、owner、公钥内容、状态、时效）。
- 禁止在密钥实体模型中固化算法字段（如 `key_exchange_algorithm`、`signature_algorithm`）。
- 算法信息属于流程协商结果，不属于目录主数据。

### 4.3 算法协商边界（强制）

- bootstrap 验签算法必须由签名请求显式声明（等价 `signed.signature_algorithm`），不得回退到密钥目录字段。
- 内部调用的传输安全实现不在全局基线中定义，避免把连接细节写入统一约定。
- 公钥目录查询不得以“密钥记录中的算法字段”作为过滤前提。

### 4.4 公钥单活约束（强制）

- 同一 owner 作用域（`entity_type + entity_id + instance_scope`）在任一时刻最多允许一条 `active` 公钥记录。
- 数据库实现必须提供等价唯一约束（例如生成列 + 唯一索引），防止出现并发双活。

---

## 5. 配置与标识来源规范（强制）

### 5.1 模块标识来源

系统模块的 ID 及其他模块级唯一标识符必须在配置文件中声明，并在模块初始化阶段读取。

### 5.2 用户标识来源

用户实体 ID 及用户身份上下文不允许由客户端或网关本地伪造；只能在认证后由后端服务返回并透传使用。

### 5.3 配置读取生命周期

统一约定：

- 服务模块与边缘端配置文件仅在初始化阶段读取一次。
- 主流程中通过参数对象/上下文对象传递，不重复从磁盘读取配置文件。
- bootstrap 所需的查钥信息必须在初始化阶段解析一次：`active_key_id`、`entity_id`（后端 `instance_id`，边缘端 `device_id`）至少提供一个，并随参数对象传递；密钥管理类运行期不得再次回读配置文件，也不得把文件名与 `key_id` 绑定。

当前状态：

- 边缘端已实现该约定。
- 后端模块尚未全面动工，后续开发必须遵循该基线。

### 5.4 Bootstrap 标识归属（强制）

统一约定：

- `active_key_id` 与 `entity_id` 不是 bootstrap 运行期反复读取的配置值，而是初始化阶段一次性解析出来的本地标识快照。
- 边缘端由 `SecretKeyUtils` 持有 `LocalTrustMaterial`，其中同时承载 `device_id` 与 `key_id`；边缘认证协调器只消费这份本地信任材料，不直接回读配置。
- gateway 与 data_worker 由 `SecretKeyService` 负责把 `ProjectConfig` 解析成 `SecretKeyStartupParams`，再把该快照交给启动期 bootstrap 编排；编排层只消费这份快照，不应自行重新读配置或从文件名反推 key id。
- gateway 与 data_worker 的 `LocalCredentialService` 只负责保存 bootstrap 成功后的本地凭证快照（`principal_id`、`active_comm_key_id`、session/token 状态），不负责本地 key 选择。
- `active_key_id` 允许为空，只要 `entity_id`（后端通常体现为 `instance_id`，边缘端体现为 `device_id`）存在即可完成 bootstrap 查钥流程。
- 认证中心不在本节约束范围内，不要求它持有或管理自身本地凭证。

---

## 6. 外部请求目标服务决策边界（强制）

统一约定：

- 外部请求到内部目标服务的映射必须由 Gateway 基于路由配置统一决策。
- 外部请求不得携带“内部目标服务标签/内部端点”作为强制路由输入。
- 若外部请求携带同类字段，Gateway 必须忽略该字段或按策略直接拒绝，不得将其作为内部转发决策依据。
- 路由策略版本、命中规则和目标服务信息应由 Gateway 侧统一记录，作为审计与故障排查依据。

---

## 7. 后端模块间通信边界（强制）

适用范围：

- 后端模块间调用（gateway、certification_server、data_worker）。

统一约定：

- 后端模块间业务请求遵循各模块既定内部调用链路，不在本文件中定义额外连接管理。

### 7.1 no-auth 运行模式例外（后端模块强制支持）

适用范围：

- 后端模块：gateway、certification_server、data_worker。

统一约定：

- 所有后端模块必须提供 `no-auth` 运行模式，用于最基本业务功能测试。
- `no-auth` 模式下默认屏蔽认证中心依赖：启动与运行不以认证中心可用为前置条件。
- `no-auth` 模式下默认短路认证链：bootstrap/session/token 相关流程不作为必经链路。
- `no-auth` 模式下默认禁用限流器（包括入站限流与转发链路限流）。
- `no-auth` 模式仅用于开发测试与联调，不作为生产运行基线。
- 认证中心在 `no-auth` 模式下默认不启动；若进程被拉起，应在判定 `run_mode=no-auth` 后自主停止，作为当前暂时性设计方向。

说明：

- 非 `no-auth` 模式仍必须遵守本章关于认证、限流与内部调用边界的强制约束。

---

## 8. 链路文档引用

- 按模块认证链路与启动链路见 `SYSTEM_AUTH_STARTUP_CHAIN_DESIGN.md`。
- 全系统 `no-auth` 启动链路与 development 对照见 `SYSTEM_NO_AUTH_STARTUP_CHAIN_DESIGN.md`。
- 边缘端认证通道与上传通道的外部接口已统一收敛到 `SYSTEM_EXTERNAL_INTERFACE_CATALOG_DESIGN.md`；网关业务转发基线见 `SYSTEM_GATEWAY_BUSINESS_FORWARDING_DESIGN.md`。

---

## 9. 跨模块职责边界（摘要）

- Gateway：公共入口与协议映射，认证相关操作统一转发认证中心；不管理他方请求主体的 challenge/session/token 状态，但需负责本模块自身凭证生命周期。
- Certification Server：认证签发、会话/令牌/通道安全控制中心。
- Data Server：业务处理与出站调用，不管理他方请求主体的 challenge/session/token 状态，但需负责本模块自身凭证生命周期。
- Data Worker：异步任务处理与出站调用，不管理他方请求主体的 challenge/session/token 状态，但需负责本模块自身凭证生命周期。
- Edge Server：本地采集/推理/上传与边缘认证协调，不直接调用认证中心。
- Client：仅走用户名密码链路，不参与密钥 bootstrap。
- 非认证中心模块不得本地签发、刷新、撤销或缓存“他方请求主体”的认证凭证状态；同时必须负责本模块自身凭证生命周期管理。
- 会话与令牌标识统一使用 `x-verified-session-id` / `x-verified-token-id` 与 `x-downstream-*-id` 规范键，避免 `-id` 与非 `-id` 分裂。
- 后端模块出站侧必须遵循对应模块的认证与路由基线，不再依赖额外连接前置条件。
- 各模块的 AuthControl 仅负责认证控制与限流；Gateway 的 AuthControl 承担全局认证确认并基于认证中心结果执行限流，非 Gateway 模块的 AuthControl 仅保留本地资源级控制与限流语义，不承担远程认证调用。
- bootstrap 与用户名密码认证成功后，认证中心返回统一凭证结果结构；当前实现以 TokenBundle 作为核心令牌子集，必要时可附加身份、会话与时间信息。调用方不得按模块拆分成功载体。
- 认证中心自身凭证不纳入当前设计边界，本轮不讨论自签发、自持有或自管理。

---

## 10. 服务发现/注册简要约定（gateway、certification_server、data_worker）

本节仅定义后续推进所需的最小统一约定，不代表已接入完整运行链路。

- 注册键路径统一为：`/bms/services/{service_name}/{instance_id}`。
- 服务实例模型统一最小字段：`id`、`service_id`、`name`、`endpoint`、`heartbeat`、`weight`、`tags`、`active_comm_key_id`、`metadata`。
- `heartbeat` 统一使用 Unix 毫秒时间戳；实例存活窗口默认 30 秒。
- 注册时 `weight` 必须大于等于 1；发现阶段在标签过滤后优先走亲和选择，其次走权重随机，最后回退轮询。
- `affinity_key` 必须通过稳定哈希算法映射到实例索引，Go 与 Python 的实现必须保持同一哈希口径，禁止使用不稳定或平台相关的散列策略。
- 权重随机选择必须基于注册后的实例权重做同口径抽样；当总权重非正时回退首个实例，禁止在不同模块间混用不同的权重归一化规则。
- `service_name` 为空时应直接返回参数错误，不进入发现选择。
- 当使用租约注册时，续约周期内必须同步刷新 `heartbeat`，避免误判实例过期。
- 服务发现/注册只提供“存活与路由筛选”能力，不作为运行期身份可信证明。

---

## 11. 模块文档引用关系

模块架构文档（仅保留层级/结构/接口）：

- `data_worker/DATA_WORKER_DESIGN_SPEC.md`
- `certification_server/CERTIFICATION_SERVER_DESIGN_SPEC.md`
- `gateway/GATEWAY_DESIGN_SPEC.md`
- `edge_server/EDGE_AUTH_DESIGN_SPEC.md`
- `edge_server/EDGE_WORKFLOW_SPEC.md`

认证与全局约定文档：

- `SYSTEM_GLOBAL_BASELINE_DESIGN.md`（本文件）
- `SYSTEM_AUTH_STARTUP_CHAIN_DESIGN.md`（模块认证链路与启动链路）
- `SYSTEM_NO_AUTH_STARTUP_CHAIN_DESIGN.md`（全系统 no-auth 启动链路与 development 对照）
- `SYSTEM_BUSINESS_MODEL_DESIGN.md`（业务模型设计说明）
- `SYSTEM_EXTERNAL_INTERFACE_CATALOG_DESIGN.md`（客户端与边缘端外部接口清单）
- `SYSTEM_GATEWAY_BUSINESS_FORWARDING_DESIGN.md`（网关业务转发基线）

## 12. 变更治理

- 新增全局约定时，先更新本文件，再更新相关模块文档中的引用。
- 若模块文档出现与本文件冲突，以本文件为准。
- 涉及接口字段变更时，必须同步更新对应契约文档与版本号。
