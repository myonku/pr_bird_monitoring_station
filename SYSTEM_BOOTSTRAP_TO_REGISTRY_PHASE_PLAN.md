# 后端 Bootstrap 到服务发现注册阶段计划

状态：Phase Plan
适用范围：gateway / certification_server / data_worker
创建目的：仅约束本轮推进，防止后续实现偏离“先打通启动链，再补业务链”的方向。

## 1. 本阶段目标

本阶段只做一件事：

- 让三个后端模块在现有代码基础上，逻辑上运行到“注册自身到服务发现”这一环节。
- 底层认证、签名、通道加密、业务处理仍保持空实现或最小骨架。
- certification_server 不要求自身 bootstrap，但必须能够完成依赖初始化并注册到服务发现。

## 2. 当前约束

- 全局约定以 SYSTEM_GLOBAL_BASELINE_DESIGN.md 为准。
- 模块链路与启动语义以 SYSTEM_AUTH_STARTUP_CHAIN_DESIGN.md 和 SYSTEM_NO_AUTH_STARTUP_CHAIN_DESIGN.md 为准。
- 本阶段不引入新的认证语义，不扩展业务协议，不重构通道实现。
- 本阶段不修改服务发现约定，不改动路由策略的大方向，只保证启动链可闭环。

## 3. 现状基线

- gateway 与 certification_server 的入口文件目前是空壳。
- data_worker 入口当前只有最小 hello world 入口。
- 三个模块都已经有注册服务、配置模型、编排骨架、路由契约和流量站点契约的雏形。
- 仓库尚无 proto 文件，因此本阶段不以 proto 落地为前置条件。

## 4. 本阶段范围

### 4.1 必做

- 统一梳理三个模块的启动入口。
- 将配置读取、依赖初始化、注册服务实例的顺序固定下来。
- 明确每个模块注册到服务发现前需要准备的最小运行态数据。
- 保持 bootstrap 相关调用链存在，但底层可以是空实现或占位返回。
- 对 certification_server 明确“无需自身 bootstrap 即可注册”的特殊规则。

### 4.2 暂不做

- 不实现真正的 challenge / signature / token / refresh 逻辑。
- 不实现真实 commsec 握手和加解密。
- 不实现完整 gRPC proto 和生成代码。
- 不实现业务转发、限流策略、二次校验、授权票据生命周期。
- 不清理与本阶段无关的历史实现碎片，除非它们直接阻断启动链。

## 5. 分阶段推进顺序

### 阶段 A：启动骨架对齐

- 确认每个模块的启动入口只做一件事：加载配置、构造依赖、装配编排、进入注册流程。
- gateway 与 data_worker 保留 bootstrap 编排入口，但内部仅串联占位实现。
- certification_server 跳过自身 bootstrap，直接进入依赖初始化与注册。

验收标准：

- 每个模块都能清晰表达启动顺序。
- 不需要业务逻辑即可走到注册前置条件。

### 阶段 B：服务发现注册闭环

- 固化注册实例所需字段：服务名、实例 ID、端点、心跳、权重、标签、活跃通信密钥引用。
- 统一注册时机为初始化完成后、稳定服务启动前。
- 明确 TTL、心跳刷新和失败回退策略的最小语义。

验收标准：

- 逻辑上每个模块都能完成“注册自身到服务发现”。
- registration 失败能够显式上抛，不能静默吞掉。

### 阶段 C：bootstrap 占位贯通

- gateway 与 data_worker 保留 bootstrap 编排调用面。
- bootstrap 仅作为流程占位，不要求真实认证中心完成权威签发。
- 认证中心不走自身 bootstrap，但仍保留本地密钥与注册前置依赖。

验收标准：

- 启动链中的 bootstrap 调用点已经明确，但可以先返回占位结果。
- 不影响注册到服务发现这一最终目标。

## 6. 约定说明

### 6.1 proto 约定

- 本阶段不要求 proto 先落地，但必须提前冻结服务与消息边界。
- 认证中心优先作为 proto 的权威服务定义源。
- 本阶段 proto 设计只追求最小集，不追求面面俱到。

建议最小范围：

- bootstrap challenge
- bootstrap authenticate
- service registration 相关信息所需的最小运行态元数据

### 6.2 路由映射策略约定

- 路由映射先按 route_key 再按 method + path + transport 归一。
- target_service_hint 只能作为提示，不得覆盖网关/模块的路由决策。
- 本阶段不新增复杂策略，只保留可以支撑启动和后续接入的最小决策面。

### 6.3 注册顺序约定

推荐顺序如下：

1. 读取配置快照。
2. 初始化本模块最小依赖。
3. 装配编排骨架。
4. 处理 bootstrap 占位或跳过逻辑。
5. 构造服务实例元数据。
6. 注册到服务发现。
7. 进入最小运行态。

## 7. 模块级关注点

### gateway

- 必须保留外部入口的语义，但当前不需要真实转发业务流量。
- bootstrap 编排链可先保持空实现，只要不阻断注册流程。
- 注册前要能生成自身实例元数据和路由所需基础上下文。

### certification_server

- 不要求自身 bootstrap。
- 启动重点是依赖初始化、本地密钥加载、服务发现注册、gRPC 骨架可用。
- 认证权威能力可以继续为空实现，但注册不能被阻断。

### data_worker

- 入口最小化，但需要形成和其他模块一致的配置-初始化-注册顺序。
- 任务处理与出站调用保持占位，先不展开。
- 若当前 Python 入口与 Go 模块结构不一致，优先统一启动顺序，不优先统一实现语言风格。

## 8. 风险控制

- 不要在本阶段引入新的协议分层名称，避免和现有文档冲突。
- 不要为了完成注册链而把认证、路由、通道逻辑提前实装。
- 不要重写现有服务发现实现，只在入口和编排层补齐连接点。
- 不要让 no-auth 语义与本阶段目标混淆；本阶段目标是逻辑注册闭环，不是完整联调环境。

## 9. 完成标志

当且仅当满足以下条件时，视为本阶段完成：

- 三个后端模块都能表达清晰的启动链。
- gateway、certification_server、data_worker 都能逻辑上走到服务发现注册步骤。
- certification_server 能在不执行自身 bootstrap 的情况下完成注册前置条件。
- 后续开始补 proto 和路由映射时，不需要重新推翻本阶段的启动顺序。

## 10. 后续衔接

- 本阶段完成后，再进入 proto 最小集冻结。
- 随后冻结路由映射策略与目标服务类型解析规则。
- 最后才补 bootstrap 真实流程、授权票据和业务转发链路。

## 11. 阶段产物（已落地）

- proto 最小集冻结说明：SYSTEM_PROTO_MINIMAL_FREEZE.md
- bootstrap 最小 proto 草案：schemas/proto/auth/v1/auth_authority_bootstrap.proto
- 路由映射策略冻结说明：SYSTEM_ROUTE_MAPPING_STRATEGY_FREEZE.md
- 注册启动链冻结说明：SYSTEM_REGISTRY_STARTUP_CHAIN_FREEZE.md
