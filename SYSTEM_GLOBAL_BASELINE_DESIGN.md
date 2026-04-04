# 系统全局基线设计说明（统一约定）

版本：1.0.0
状态：Baseline

## 1. 文档目的

本说明作为工作区级全局规范，统一以下内容：

- 跨模块统一约定（ID 规范、密钥规范、配置规范、初始化约定）。
- 模块间职责边界和实现前置约束。

说明：

- 各模块内设计文档仅保留层级/结构/接口等架构信息。
- 全局统一约定以本文件为唯一基准。
- 按模块认证链路与启动链路见 `SYSTEM_AUTH_STARTUP_CHAIN_DESIGN.md`。
- 边缘端认证与上传通信协议细节继续以 `edge_server/EDGE_GATEWAY_CHANNEL_INTERFACE_CONTRACT.md` 为准（该文档不在本次重构范围内）。

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
- 公钥校验查询支持两种入口：
	- 按 `key_id` 精确查询。
	- 按关联 `entity_id` 查询当前可用公钥（用于 `key_id` 缺失或不确定场景）。
- 模块配置文件至少应包含一个可用键（active key），并可由认证中心通过 `entity_id` 反查到对应公钥记录。

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

## 6. 链路文档引用

- 按模块认证链路与启动链路见 `SYSTEM_AUTH_STARTUP_CHAIN_DESIGN.md`。
- 边缘端认证通道与上传通道的接口契约见 `edge_server/EDGE_GATEWAY_CHANNEL_INTERFACE_CONTRACT.md`。

---

## 7. 跨模块职责边界（摘要）

- Gateway：公共入口与协议映射，不实现认证中心核心签发逻辑。
- Certification Server：认证签发、会话/令牌/通道安全控制中心。
- API Service：业务处理与出站调用，不承载认证中心职责。
- Edge Server：本地采集/推理/上传与边缘认证协调，不直接调用认证中心。
- Client：仅走用户名密码链路，不参与密钥 bootstrap。

---

## 8. 模块文档引用关系

模块架构文档（仅保留层级/结构/接口）：

- `api_service/API_SERVICE_DESIGN_SPEC.md`
- `certification_server/CERTIFICATION_SERVER_DESIGN_SPEC.md`
- `gateway/GATEWAY_DESIGN_SPEC.md`
- `edge_server/EDGE_AUTH_DESIGN_SPEC.md`
- `edge_server/EDGE_WORKFLOW_SPEC.md`

认证与全局约定文档：

- `SYSTEM_GLOBAL_BASELINE_DESIGN.md`（本文件）
- `SYSTEM_AUTH_STARTUP_CHAIN_DESIGN.md`（模块认证链路与启动链路）
- `edge_server/EDGE_GATEWAY_CHANNEL_INTERFACE_CONTRACT.md`（边缘通信契约）
- `CLIENT_AUTH_DESIGN_SPEC.md`（客户端认证索引）

---

## 9. 变更治理

- 新增全局约定时，先更新本文件，再更新相关模块文档中的引用。
- 若模块文档出现与本文件冲突，以本文件为准。
- 涉及接口字段变更时，必须同步更新对应契约文档与版本号。
