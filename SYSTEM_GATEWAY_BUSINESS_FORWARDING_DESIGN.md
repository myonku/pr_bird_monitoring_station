# 网关业务转发设计说明

版本：1.0.0
状态：Baseline
适用模块：`gateway`

## 1. 文档目的

本文件只固定网关的业务转发基准，目标是：

- 将外部 HTTP 业务请求统一收敛为一条内部业务 gRPC 通道。
- 将认证转发与业务转发分离，避免把认证链路和业务链路混成一套接口。
- 让目标服务在 gRPC 入站之后按 route / operation 分发到具体服务层函数，而不是为每个外部 HTTP 接口扩展一条独立 gRPC 通道。

本文件不展开认证中心内部实现，也不定义完整业务模型，只固定网关侧的转发边界与最小字段语义。

## 2. 核心约束

- `gateway` 是外部请求进入后端的唯一决策点。
- 外部业务请求不得携带内部目标服务作为强制路由输入。
- `target_service_hint` 仅在可信内部调用场景下生效，外部请求必须忽略或拒绝。
- 业务路由以 `route_key` 为主标识，`operation` 作为目标服务内部的细粒度分发键。
- `business.forward.generic` 仍是当前阶段的业务路由基线占位。
- 网关到目标服务之间只保留一条逻辑上的统一业务 gRPC 通道，不为单个外部 HTTP 接口新增独立 gRPC 方法。
- 非 `no_auth` 模式下，业务请求在转发前必须先完成统一认证头校验与 `authcontrol` 决策。
- `no_auth` 模式下必须禁用 `authcontrol` 与相关限流路径，但仍保留路由解析与业务转发能力。

## 3. 请求处理基线

网关业务请求的推荐处理顺序如下：

1. HTTP 入站标准化。
2. 读取统一认证头与基础请求上下文。
3. 组装 `FlowRouteInput`，固定字段包括 `route_key`、`transport`、`method`、`path`、`source_service`、`metadata`。
4. 通过路由快照解析 `RouteProfile`，确定 `flow_category`、`target_service_type`、`target_service_name`、`target_endpoint`。
5. 非 `no_auth` 模式下，先调用认证中心相关能力完成校验，再执行 `authcontrol` 限流与放行判断。
6. 认证通过且路由命中后，交由统一业务编排器选择目标实例并构造业务 gRPC 请求。
7. 业务 gRPC 请求发往目标服务的统一入口，由目标服务在 gRPC 层下游继续分发到 service layer。

认证转发是并行但独立的路径：`auth.*` 类路由继续使用现有认证 RPC 客户端，业务转发不复用认证转发通道。

## 4. 统一业务 gRPC 通道

统一业务 gRPC 通道的设计原则是“单入口、强 envelope、弱耦合”。

- 单入口：每个目标服务模块只保留一个统一的业务 gRPC 入口，不按业务场景扩展一组一组的新 RPC。
- 强 envelope：网关传给目标服务的请求必须携带完整路由与上下文信息。
- 弱耦合：目标服务只根据 `route_key` / `operation` / `metadata` 做本地分发，不反向依赖网关 HTTP 路径。

建议的统一业务请求字段如下：

- `route_key`
- `operation`
- `flow_category`
- `source_service`
- `target_service_type`
- `target_service_name`
- `target_endpoint`
- `request_id`
- `trace_id`
- `headers`
- `auth_context`
- `metadata`
- `payload`

建议的统一业务响应字段如下：

- `accepted`
- `status`
- `route_key`
- `operation`
- `target_service_name`
- `target_endpoint`
- `payload`
- `metadata`
- `error_code`
- `error_message`

对应 proto 基线见 [`schemas/proto/business/v1/business_forward.proto`](schemas/proto/business/v1/business_forward.proto)。

## 5. 目标服务侧分发模型

目标服务在 gRPC 入站后，不应直接把每个外部 HTTP 接口映射成独立 RPC 方法，而应采用以下方式：

- 统一业务入口接收 envelope。
- 服务内建立 `route_key -> handler` 或 `operation -> handler` 的分发表。
- 由 dispatcher 继续调用 service layer / usecase。
- 业务模型和业务处理函数可以继续拆分，但 RPC 接口保持收敛。

这样做的直接收益是：

- 不需要为每个页面动作或每个业务查询新增一套 gRPC 方法。
- 网关只维护一套路由与一套统一业务通道。
- 业务迭代时优先扩展 `route_key` 和 `operation`，而不是无限扩展 proto surface。

## 6. 模式差异

### 6.1 development

- 启用认证转发。
- 启用 `authcontrol`。
- 业务请求在转发前完成统一认证头校验。
- 限流策略和路由快照都参与决策。

### 6.2 no_auth

- 禁用认证控制与限流。
- 业务请求只做路由解析和目标服务选择。
- 安全策略降为 `disabled`。
- 业务统一 gRPC 通道仍然保留，用于最基本联调。

## 7. 非目标

- 不在本文件定义每个外部 HTTP 接口到每个内部 gRPC 方法的一一对应关系。
- 不在本文件定义认证中心的完整 RPC 业务语义。
- 不在本文件定义目标服务内部的业务逻辑实现。
- 不在本文件恢复被裁撤的并行转发通道或目标侧二次复核设计。
