# 系统 no-auth 运行模式启动链路说明（对照 development）

版本：1.1.0
状态：Baseline

## 1. 文档目的

本说明定义全系统 no-auth 运行模式的启动链路，并与现有 development 链路做并列对照，用于在认证体系未完成前支持最基本业务功能测试。

本说明覆盖：

- 后端模块 no-auth 启动链路（gateway、certification_server、data_worker）。
- 边缘端 no-auth 与孤岛模式（island）对照。
- 每个模块在 no-auth 下的启用行为与禁用行为。

本说明不替代现有链路文档：

- development 与认证主干链路仍以 SYSTEM_AUTH_STARTUP_CHAIN_DESIGN.md 为准。
- 全局强制约束仍以 SYSTEM_GLOBAL_BASELINE_DESIGN.md 为准。

---

## 2. 术语与适用范围

术语定义：

- development：当前默认开发联调链路（含认证中心、回源认证、限流、commsec 握手与加密约束）。
- no-auth：后端最小业务测试模式，默认屏蔽认证中心、短路认证链、禁用限流、关闭模块间握手与应用层加密。
- edge island：边缘端孤岛模式（本地采集/推理/落盘，不执行对外上传）。

适用模块：

- gateway
- certification_server
- data_worker
- edge_server

---

## 3. 全局行为对照矩阵

| 行为项                       | development（后端）  | no-auth（后端）      | edge no-auth | edge island（development） |
| ---------------------------- | -------------------- | -------------------- | ------------ | -------------------------- |
| 认证中心依赖                 | 必需                 | 屏蔽                 | 屏蔽         | 屏蔽                       |
| bootstrap/session/token 链路 | 启用                 | 短路                 | 短路         | 关闭                       |
| downstream grant             | 启用                 | 短路                 | 不适用       | 不适用                     |
| 入站回源认证校验             | 启用                 | 关闭                 | 不适用       | 不适用                     |
| 限流器                       | 启用                 | 关闭                 | 不适用       | 不适用                     |
| EnsureChannel 握手           | 启用                 | 关闭                 | 关闭         | 关闭                       |
| 应用层加密（commsec）        | 启用                 | 关闭                 | 关闭         | 关闭                       |
| 外部请求目标路由决策         | Gateway 路由配置     | Gateway 路由配置     | 不适用       | 不适用                     |
| 外部输入内部目标标签         | 忽略或拒绝           | 忽略或拒绝           | 不适用       | 不适用                     |
| 对外业务上传                 | 按策略与网络状态执行 | 按策略与网络状态执行 | 启用         | 关闭                       |

---

## 4. Gateway 启动链对照

### 4.1 development 启动链

1. 读取配置并初始化 repo/发现/路由组件。
2. 执行 bootstrap 就绪检查，持有本模块认证状态。
3. 预热关键下游通道（EnsureChannel）。
4. 装配限流与认证相关中间链路。
5. 启动对外入站服务并进入稳定转发。

### 4.2 no-auth 启动链

1. 读取配置并初始化 repo/发现/路由组件。
2. 跳过 bootstrap 与认证中心可用性检查。
3. 跳过通道预热与 EnsureChannel。
4. 装配 no-auth 安全准备器（保持统一转发结构，但不执行鉴权、握手和加密）。
5. 关闭限流链后启动入站服务。

### 4.3 行为开关

启用：

- 路由解析与转发。
- 服务发现与实例选择。
- 业务协议映射。

禁用：

- bootstrap/refresh/verify/revoke/grant。
- 入站/出站限流决策。
- commsec 握手、通道检查与应用层加解密。

---

## 5. API Service 启动链对照

### 5.1 development 启动链

1. 读取配置并初始化依赖。
2. 执行 readiness（含 bootstrap 认证就绪）。
3. 装配入站认证中心回源校验拦截器。
4. 装配限流拦截器。
5. 启动 gRPC 入站服务。

### 5.2 no-auth 启动链

1. 读取配置并初始化依赖。
2. 跳过 readiness 中的认证前置检查。
3. 不装配回源认证拦截器。
4. 不装配限流拦截器。
5. 启动最小业务 gRPC 入站服务。

### 5.3 行为开关

启用：

- 入站业务处理主链路。
- 基础健康检查与运行时依赖。

禁用：

- 回源认证校验。
- 认证上下文强校验分支。
- 限流与配额判定。
- commsec 相关握手与应用层加解密。

---

## 6. Certification Server 启动链对照

### 6.1 development 启动链

1. 初始化 auth/commsec/ratelimit/orchestration 组件。
2. 启动认证与通道能力接口。
3. 进入认证与通信安全请求处理循环。

### 6.2 no-auth 启动链

1. 初始化最小服务骨架。
2. 关闭认证签发、校验、刷新、撤销主链路。
3. 关闭限流链路。
4. 关闭通道握手与应用层加解密链路。
5. 启动仅用于联调占位的最小接口（或按部署策略不启动本模块）。

### 6.3 行为开关

启用：

- 最小可用进程能力（健康检查、基础服务壳）。

禁用：

- challenge/bootstrap/token/session/downstream grant。
- 限流决策。
- commsec 握手、通道管理、加解密编排。

---

## 7. Data Worker 启动链对照

### 7.1 development 启动链

1. 初始化配置、队列/存储依赖。
2. 执行认证相关 readiness。
3. 装配限流与通信安全前置。
4. 进入任务消费与处理循环。

### 7.2 no-auth 启动链

1. 初始化配置、队列/存储依赖。
2. 跳过认证 readiness。
3. 关闭限流链。
4. 关闭 commsec 握手与加密要求。
5. 进入最小任务处理循环。

### 7.3 行为开关

启用：

- 最小任务消费与处理。
- 基础存储与状态更新。

禁用：

- 认证中心依赖链路。
- 限流链路。
- 模块间握手与应用层加密。

---

## 8. Edge Server 双模式对照（no-auth 与 island）

### 8.1 Edge no-auth 启动链

1. 读取配置并初始化采集/推理/上传/spool 组件。
2. 初始化 no-auth 占位认证协调器（接口保留，认证流程短路）。
3. 启动主流程（采集 -> 决策 -> 推理 -> 上传）。
4. 启动补传 worker。

启用：

- 本地采集与推理。
- 实时上传与补传。

禁用：

- bootstrap/refresh/unauthorized 恢复。
- 对外认证头有效值（返回空值）。
- 与后端模块的握手和应用层加密要求。

### 8.2 Edge island 启动链（对照 development）

1. 读取配置并初始化采集/推理/spool 组件。
2. 不初始化认证模块。
3. 网络状态固定为不可上传。
4. 启动主流程（采集 -> 决策 -> 推理 -> 本地落盘）。
5. 不执行补传 worker 对外上传。

启用：

- 本地采集与推理。
- 本地落盘缓存。

禁用：

- 全部对外上传行为。
- 认证与限流相关链路。
- 握手与应用层加密。

---

## 9. 使用约束

- no-auth 仅用于“最基本业务功能测试”与联调提速，不作为生产运行方案。
- 进入 development 或更高环境前，必须恢复认证链路、限流链路、握手与加密链路。
- 外部请求目标服务决策始终由 Gateway 路由配置负责，不因 no-auth 模式改变。

---

## 10. 后端 no-auth 启动链执行细则（补充）

本节补充后端模块在 no-auth 模式下的统一执行细则，用于和 development 模式形成可比对的最小执行基准。

### 10.1 统一顺序（后端三模块）

1. 读取配置快照（仅一次）。
2. 规范化运行时标识（service_name、instance_id、端口、run_mode=no-auth）。
3. 初始化基础依赖（至少 etcd 客户端与注册服务）。
4. 初始化本地密钥服务并读取 active_key_id（供实例元数据与后续模式切换复用）。
5. no-auth 分支处理：
	- gateway/data_worker：跳过 bootstrap 调用。
	- certification_server：可不启动；若启动则跳过自身 bootstrap。
6. 构造 ServiceInstance 元数据。
7. 调用注册服务写入服务发现。
8. 启动最小入站能力并进入运行态。

### 10.2 失败处理约束

- 配置解析失败：立即失败退出，不注册。
- 依赖初始化失败：立即失败退出，不注册。
- 注册失败：立即失败退出，不进入最小运行态。
- 注册成功后入站启动失败：必须 best-effort 注销实例后退出。

### 10.3 注册实例与键路径约束

注册实例最小字段：

- id
- service_id
- name
- endpoint
- heartbeat
- weight
- tags
- active_comm_key_id
- metadata

补充规则：

- heartbeat 为空时由注册服务填充当前毫秒时间。
- weight 小于等于 0 时归一为 1。
- 注册键路径统一为 `/bms/services/{service_name}/{instance_id}`。

### 10.4 阶段日志最小集

每个后端模块至少输出以下阶段日志：

- config_loaded
- dependencies_initialized
- bootstrap_skipped_or_ready
- registry_register_attempt
- registry_register_success
- server_start_attempt
- server_start_success

失败路径至少记录：

- stage
- error
- request_id 或 trace_id（若可用）

### 10.5 文档引用补充

- 路由与 proto 合并基准见 `SYSTEM_BACKEND_ROUTE_PROTO_BASELINE.md`。
- 后端启动链路阶段记录与时间线见 `SYSTEM_BACKEND_STARTUP_PROGRESS_TIMELINE.md`。
