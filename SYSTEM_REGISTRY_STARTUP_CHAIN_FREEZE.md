# 后端注册启动链冻结说明

状态：Frozen-Minimal
阶段：Bootstrap to Registry
适用模块：gateway / certification_server / data_worker

## 1. 目标

本文件冻结本阶段唯一启动目标：

- 三个后端模块都能逻辑上走到服务发现注册。
- gateway 与 data_worker 保留 bootstrap 调用位，但允许底层为空实现。
- certification_server 不执行自身 bootstrap，仍可完成注册。

## 2. 全局启动约束

### 2.1 顺序约束（强制）

所有后端模块必须遵循统一顺序：

1. 读取配置快照（仅一次）。
2. 规范化运行时标识（entity_type、service_name、instance_id、端口、run_mode）。
3. 初始化基础依赖（至少 etcd 客户端与注册服务）。
4. 初始化本地密钥服务（读取 active_key_id 与密钥目录）。
5. 执行模块级 bootstrap 分支或跳过分支。
6. 构造 ServiceInstance 元数据。
7. 调用注册服务写入服务发现。
8. 启动最小入站能力并进入运行态。

### 2.2 失败处理约束（强制）

- 配置解析失败：立即失败退出，不注册。
- 依赖初始化失败：立即失败退出，不注册。
- bootstrap 分支失败（gateway/data_worker）：立即失败退出，不注册。
- 注册失败：立即失败退出，不进入最小运行态。
- 注册成功后启动入站失败：必须 best-effort 注销自身实例后退出。

### 2.3 no-auth 约束（强制）

- no-auth 模式下，gateway 与 data_worker 跳过 bootstrap 调用。
- no-auth 模式下仍允许注册到服务发现（用于最小联调）。
- certification_server 可按部署策略不启动；若启动则不执行自身 bootstrap。

## 3. 服务实例元数据冻结

注册时必须至少填充以下字段：

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
- instance_id 必须可映射为实例唯一标识。
- 注册键路径统一遵循 /bms/services/{service_name}/{instance_id}。

## 4. 模块级启动链冻结

### 4.1 gateway

目标：启动到注册成功，再启动最小 HTTP 入站骨架。

固定步骤：

1. 加载 settings.toml 并解析 runtime/auth。
2. 初始化 etcd 客户端与 RegistryService。
3. 初始化 SecretKeyService，解析 active_key_id。
4. 分支：
   - development：调用 bootstrap coordinator 的 ensure ready 占位。
   - no-auth：跳过 bootstrap。
5. 构造 ServiceInstance（name 固定为 gateway，endpoint 为 host:http_port）。
6. 调用 registry register。
7. 启动最小 HTTP server（可仅保留健康检查或空路由）。

### 4.2 certification_server

目标：不经自身 bootstrap，直接完成注册并启动最小 gRPC 入站骨架。

固定步骤：

1. 加载 settings.toml 并解析 runtime/auth。
2. 初始化 mysql/redis/etcd 的最小可用依赖。
3. 初始化 SecretKeyService（本地单活密钥对用于 commsec 预备）。
4. 明确跳过自身 bootstrap。
5. 构造 ServiceInstance（name 固定为 certification_server，endpoint 为 host:grpc_port）。
6. 调用 registry register。
7. 启动最小 gRPC server 骨架。

### 4.3 data_worker

目标：启动到注册成功，再进入最小任务循环或最小 gRPC 入站骨架。

固定步骤：

1. 加载 settings.toml 并解析 runtime/auth。
2. 初始化 etcd 客户端与 RegistryService。
3. 初始化 SecretKeyService，解析 active_key_id。
4. 分支：
   - development：调用 bootstrap coordinator 的 ensure ready 占位。
   - no-auth：跳过 bootstrap。
5. 构造 ServiceInstance（name 固定为 data_worker，endpoint 为 host:grpc_port）。
6. 调用 registry register。
7. 启动最小任务处理循环或最小 gRPC server 骨架。

## 5. 运行模式分支表

| 模块 | development | no-auth |
| --- | --- | --- |
| gateway | 执行 bootstrap 占位后注册 | 跳过 bootstrap，直接注册 |
| certification_server | 跳过自身 bootstrap，直接注册 | 可不启动；若启动则跳过自身 bootstrap 后注册 |
| data_worker | 执行 bootstrap 占位后注册 | 跳过 bootstrap，直接注册 |

## 6. 可执行落地清单

### 6.1 入口层

- gateway main 负责串联配置读取、依赖装配、注册、HTTP 启动。
- certification_server main 负责串联配置读取、依赖装配、注册、gRPC 启动。
- data_worker main 负责串联配置读取、依赖装配、注册、最小循环启动。

### 6.2 编排层

- gateway/data_worker 的 bootstrap coordinator 保持接口不变，先用占位返回。
- certification_server 不增加自身 bootstrap 编排入口。

### 6.3 注册层

- 统一使用现有 RegistryService。
- TTL 建议默认 30 秒。
- 若注册成功后进程退出，需尝试调用 unregister。

## 7. 日志与观测最小集

每个模块至少记录以下阶段日志：

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

## 8. 与已冻结文档联动

本文件与以下文档共同构成本阶段实现输入：

- SYSTEM_BOOTSTRAP_TO_REGISTRY_PHASE_PLAN.md
- SYSTEM_PROTO_MINIMAL_FREEZE.md
- SYSTEM_ROUTE_MAPPING_STRATEGY_FREEZE.md

若启动顺序或 route_key 发生变更，需同步更新以上文档并递增版本标识。

## 9. 本阶段完成判定

满足以下条件即判定“注册启动链制定完成”：

- 三模块都具备统一且可执行的启动顺序定义。
- certification_server 跳过自身 bootstrap 的规则明确且不含歧义。
- 注册失败与启动失败的回退策略被显式定义。
- 后续代码实现可直接按本文件逐项落地，无需再次补充流程级规则。
