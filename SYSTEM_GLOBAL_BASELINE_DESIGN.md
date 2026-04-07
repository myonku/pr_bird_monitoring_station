# 系统全局基线设计说明（统一约定）

版本：1.1.0
状态：Baseline

## 1. 文档目的

本说明作为工作区级全局规范，统一以下内容：

- 跨模块统一约定（ID 规范、密钥规范、配置规范、初始化约定）。
- 模块间职责边界和实现前置约束。

说明：

- 各模块内设计文档仅保留层级/结构/接口等架构信息。
- 全局统一约定以本文件为唯一基准。
- 按模块认证链路与启动链路见 `SYSTEM_AUTH_STARTUP_CHAIN_DESIGN.md`。
- 边缘端认证与上传通信协议细节的独立契约文档待重建（当前暂时下线）。

---

## 2. 适用范围

适用于以下模块：

- gateway
- certification_server
- api_service
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

适用对象：除客户端之外的系统模块（gateway、api_service、edge_server、data_worker 等）。

统一要求：

- 本地仅允许存在一对当前生效密钥（单活）。
- 私钥格式固定为 PKCS#8 PEM。
- 公钥格式固定为 SPKI PEM。
- 密钥轮换时必须先切换新单活密钥，再安全退役旧密钥。

边界说明：

- 认证中心不持有业务模块私钥原文，仅校验公钥目录与签名结果。
- 客户端不参与本地密钥 bootstrap。

公钥目录约束：

- 系统内所有需要记录公钥的非客户端实体（service/device/gateway/worker 等）统一使用同一张公钥目录表结构，不按模块拆分多套结构。
- 公钥查询必须收敛为统一目录查询请求（等价 `LookupPublicKey` 语义），至少支持三种检索条件：
  - 按 `key_id` 精确查询。
  - 按 `entity_id` 查询当前可用公钥（用于 `key_id` 缺失或不确定场景）。
  - 按 owner 维度查询（`entity_type + entity_id + instance_id`）。
- 查询请求必须支持 `require_active` 等价语义，要求仅返回当前激活密钥。
- 模块配置文件至少应包含一个可用键（active key），并可由认证中心通过 `entity_id` 反查到对应公钥记录。

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
- commsec 握手算法（密钥交换/签名/套件）必须在握手流程中由双方能力集合协商产生。
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

当前状态：

- 边缘端已实现该约定。
- 后端模块尚未全面动工，后续开发必须遵循该基线。

---

## 6. 内部转发双端认证校验机制（强制）

统一约定：

- Gateway 在对内转发前必须向认证中心完成该跳认证准备（至少包含凭证校验与下游 grant 申请），并注入下游认证上下文头。
- 目标模块接收到内部请求后，必须再次向认证中心发起认证校验（至少会话有效性校验；按场景补充令牌校验），不得仅凭网关注入头放行。
- 下游认证上下文头最小集为：`x-downstream-principal`、`x-downstream-session-id`、`x-downstream-token-id`。
- 双端回源校验失败必须快速失败并返回显式错误，禁止静默降级。

实现边界：

- 认证中心仍是签发权威与公钥目录权威。
- 服务发现/注册信息仅用于存活与路由筛选，不作为身份可信证明。

---

## 7. 后端模块间加密信道约束（强制）

适用范围：

- 后端模块间调用（gateway、certification_server、api_service、data_worker）。

统一约定：

- 后端模块间业务请求必须运行在 commsec 安全通道上，不得以明文请求直连作为运行期兜底。
- 安全通道握手初始化优先在 bootstrap/readiness 阶段完成预热；若未预热，必须在首次业务通信前由主动方执行 EnsureChannel 并完成握手。
- 仅允许在“握手成功 + 通道有效”状态发送业务 payload；握手失败必须快速失败并返回显式错误。
- 允许复用存量有效通道，但在通道过期、撤销或协商参数失配时必须重新握手，禁止绕过通道状态检查。

运行期观测最小集：

- `secure_channel_handshake_attempt_total`
- `secure_channel_handshake_failed_total`
- `secure_channel_reuse_total`

---

## 8. 链路文档引用

- 按模块认证链路与启动链路见 `SYSTEM_AUTH_STARTUP_CHAIN_DESIGN.md`。
- 边缘端认证通道与上传通道的接口契约文档待重建（当前暂时下线）。

---

## 9. 跨模块职责边界（摘要）

- Gateway：公共入口与协议映射，认证相关操作统一转发认证中心；不管理他方请求主体的 challenge/session/token/grant 状态，但需负责本模块自身凭证生命周期。
- Certification Server：认证签发、会话/令牌/通道安全控制中心。
- API Service：业务处理与出站调用，认证相关操作统一转发认证中心；不管理他方请求主体的 challenge/session/token/grant 状态，但需负责本模块自身凭证生命周期。
- Edge Server：本地采集/推理/上传与边缘认证协调，不直接调用认证中心。
- Client：仅走用户名密码链路，不参与密钥 bootstrap。
- 非认证中心模块不得本地签发、刷新、撤销或缓存“他方请求主体”的认证凭证状态；同时必须负责本模块自身凭证生命周期管理。
- 内部限流描述符主体来源统一为“认证中心复核后的身份上下文”（verified identity），不再以原始转发头作为主依据。
- 会话与令牌标识统一使用 `x-verified-session-id` / `x-verified-token-id` 与 `x-downstream-*-id` 规范键，避免 `-id` 与非 `-id` 分裂。
- API Service 运行期会话/令牌回源校验路径必须保留并作为内部转发默认校验路径。
- 运行期告警指标至少覆盖：回源认证校验失败量、回源认证超时量。
- 后端模块出站侧必须先确保安全通道可用（预热复用或首跳握手），之后才允许发送业务 payload。

---

## 10. 服务发现/注册简要约定（gateway、certification_server、api_service）

本节仅定义后续推进所需的最小统一约定，不代表已接入完整运行链路。

- 注册键路径统一为：`/bms/services/{service_name}/{instance_id}`。
- 服务实例模型统一最小字段：`id`、`service_id`、`name`、`endpoint`、`heartbeat`、`weight`、`tags`、`active_comm_key_id`、`metadata`。
- `heartbeat` 统一使用 Unix 毫秒时间戳；实例存活窗口默认 30 秒。
- 注册时 `weight` 必须大于等于 1；发现阶段在标签过滤后优先走亲和选择，其次走权重随机，最后回退轮询。
- `service_name` 为空时应直接返回参数错误，不进入发现选择。
- 当使用租约注册时，续约周期内必须同步刷新 `heartbeat`，避免误判实例过期。
- 服务发现/注册只提供“存活与路由筛选”能力，不作为运行期身份可信证明。

---

## 11. 模块文档引用关系

模块架构文档（仅保留层级/结构/接口）：

- `api_service/API_SERVICE_DESIGN_SPEC.md`
- `certification_server/CERTIFICATION_SERVER_DESIGN_SPEC.md`
- `gateway/GATEWAY_DESIGN_SPEC.md`
- `edge_server/EDGE_AUTH_DESIGN_SPEC.md`
- `edge_server/EDGE_WORKFLOW_SPEC.md`

认证与全局约定文档：

- `SYSTEM_GLOBAL_BASELINE_DESIGN.md`（本文件）
- `SYSTEM_AUTH_STARTUP_CHAIN_DESIGN.md`（模块认证链路与启动链路）
- 边缘通信契约文档待重建（当前暂时下线）
- `CLIENT_AUTH_DESIGN_SPEC.md`（客户端认证索引）

---

## 12. 变更治理

- 新增全局约定时，先更新本文件，再更新相关模块文档中的引用。
- 若模块文档出现与本文件冲突，以本文件为准。
- 涉及接口字段变更时，必须同步更新对应契约文档与版本号。
