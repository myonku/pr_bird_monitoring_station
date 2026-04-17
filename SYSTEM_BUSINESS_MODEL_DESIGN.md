# 系统业务模型设计说明（草案）

版本：0.1.0
状态：Draft
适用范围：边缘端采集、data_worker 处理、未来面向客户端的业务接口模块、Flutter 客户端读模型

## 1. 文档目的

本文件用于描述鸟类监测系统的业务模型边界，重点回答三件事：

- 业务到底围绕哪些实体展开。
- 从边缘端上传到客户端展示，中间应当如何分层处理。
- 当前客户端已经实现的展示字段，应当对应到哪些读模型。

本文件只定义业务语义，不落实现代码，也不绑定具体数据库选型。

## 2. 设计前提

- `data_worker` 是业务服务模块的一部分，但它主要负责处理边缘端上传的事件，必要时使用通用模型做补充识别，再把结果写入数据库。
- 系统的业务模块只保留两个：`data_worker` 与 `data_server`。
- `data_worker` 负责接收边缘端上传的事件，执行可选的服务端处理或补充识别，再把标准化结果写入数据库。
- `data_server` 负责面向客户端的业务请求接口，除登录等认证相关接口外，对外提供业务查询、列表、详情和统计能力。
- 当前阶段不把边缘端上传数据严格映射成业务模型；上传数据先作为“事件”接收，再由接收端解析、归一化和落库。
- `Device` 是后端正式实体名称，`Station` 只保留给客户端展示层。一个野外部署点就是一套树莓派设备 + 边缘端服务，业务上以 `Device` 为主。
- `UserProfile`、边缘事件原始 payload 和 binary part 内容优先采用 Mongo 文档存储，MySQL 只保留稳定引用与聚合记录。
- `user` 指的是面向数据展示的普通使用者，不是设备管理员。管理员角色可以后续再引入，但不进入当前模型范围。
- 业务存储可以使用 Mongo 或 MySQL；模型层只保证字段语义稳定，不固定持久化实现。

## 3. 端到端业务流

系统里实际有两条业务主路径：

1. 边缘事件路径：边缘端采集画面、触发抓拍，并组装一次上传事件；事件经由网关进入 `data_worker`，`data_worker` 负责解析、校验、可选的服务端补充识别与归一化落库。
2. 客户端业务路径：Flutter 客户端通过网关访问 `data_server`，`data_server` 负责读取业务库中的记录、聚合结果和读模型，对外提供首页、记录、详情和统计等业务查询接口。

这两条路径共享同一套业务事实来源，但职责不同：`data_worker` 负责把事件变成标准业务记录，`data_server` 负责把标准业务记录变成客户端可消费的业务接口。

这条链路的核心原则是：边缘事件不等于业务记录，业务记录也不等于客户端展示项。中间需要一个“解析 + 归一化 + 聚合”的过程。

## 4. 业务域划分

### 4.1 设备域

当前业务只保留 `Device` 作为主实体。

- 一个 `Device` 代表一个野外部署点。
- 这个部署点对应一套硬件平台和边缘端运行环境。
- `Station` 只保留给客户端展示层命名，不进入后端正式模型。
- 如果后续出现多机位或多设备复用，再考虑拆分更细的硬件层模型；当前阶段不拆。

建议字段：

- `device_entity_id`
- `device_name`
- `status`
- `last_heartbeat_ms`
- `metadata`

### 4.2 事件接入域

边缘端上传的数据应视为事件信封，而不是业务核心实体。

建议使用一个宽松的接入模型，例如 `EdgeEventEnvelope`：

- `event_id`
- `device_entity_id`
- `occurred_at_ms`
- `received_at_ms`
- `payload_version`
- `payload_type`
- `payload_body`
- `payload_mongo_document_id`
- `transport_meta`

这个模型的关键点是“可变”和“可扩展”。它不要求一开始就和业务记录字段一一对应，接收端可以在解析时决定如何归一化。

### 4.3 处理域

`data_worker` 处理事件时，会产生一组中间态模型：

- `ProcessingJob`：描述一次处理任务本身。
- `RecognitionResult`：描述模型识别结果或补充识别结果。

这些模型主要服务于处理流程和故障恢复，不应该直接作为客户端展示模型。

建议字段：

`ProcessingJob`：

- `job_id`
- `source_event_id`
- `device_entity_id`
- `status`
- `processor`
- `retry_count`
- `started_at_ms`
- `finished_at_ms`
- `error_message`

`RecognitionResult`：

- `result_id`
- `source_event_id`
- `species_name`
- `scientific_name`
- `confidence`
- `model_name`
- `model_version`
- `produced_by`（edge / data_worker）

### 4.4 业务记录域

业务记录的核心实体建议定义为 `MonitoringRecord`。

它是被持久化、可查询、可统计的标准业务记录，来源可以是：

- 边缘端已经完成识别后的结果。
- 边缘端未完成识别，由 `data_worker` 补充识别后的结果。

建议字段：

- `record_id`
- `device_entity_id`
- `source_event_id`
- `captured_at_ms`
- `species_name`
- `scientific_name`
- `confidence`
- `temperature_c`
- `humidity_pct`
- `media_refs`
- `processing_source`
- `model_version`
- `summary_text`
- `species_intro`
- `record_status`

说明：

- `MonitoringRecord` 才是后端最应该稳定下来的业务主记录。
- 记录里的 `species_intro` 可以来自参考数据表，也可以在后续服务返回时补充，不要求边缘端原样上传。
- `record_status` 只反映记录生命周期，不表示人工审核流程，因为当前阶段没有引入复杂审核域。

补充说明：

- `data_worker` 是 `MonitoringRecord` 的主要写入方。
- `data_server` 是 `MonitoringRecord`、聚合结果与读模型的主要查询出口。
- `data_server` 不直接消费原始边缘 payload 作为对外业务接口输入。

### 4.5 统计读模型域

客户端展示需要的统计数据应该作为读模型存在，而不是临时现场拼接。

建议读模型：

- `DashboardSnapshot`
- `RecordListItem`
- `RecordDetailView`
- `TrendPoint`
- `SpeciesShare`

说明：

- 读模型可以比核心业务记录更扁平、更适合接口输出。
- 读模型允许冗余和字段拼装，不要求和数据库表完全同构。
- 这些读模型主要由 `data_server` 对外提供，通常由 `MonitoringRecord` 和统计聚合结果派生而来。

### 4.6 用户域

`user` 这里指的是客户端数据查看用户，不是设备管理人员。

建议使用 `ViewerUser` 或继续沿用 `AppUser` 作为展示侧用户模型。

建议字段：

- `user_id`
- `name`
- `role`（当前默认为 viewer）
- `phone`
- `avatar_seed`

说明：

- 当前不纳入管理员、站点运维员、设备运维员等角色模型。
- 后续如果要扩展角色体系，应单独增加权限域，而不是污染当前展示用户模型。

### 4.7 参考数据域

物种简介、展示文案、基础分类信息建议放入参考数据域，例如 `SpeciesProfile`。

建议字段：

- `species_name`
- `scientific_name`
- `intro`
- `display_name`

这类数据属于知识参考，不是每条记录都必须强绑定的核心业务事实。

## 5. 模型关系

推荐关系如下：

- 一个 `Device` 对应一个业务部署单元。
- 一个 `EdgeEventEnvelope` 可能生成一次或多次 `ProcessingJob`，视重试或补处理策略而定。
- 一个 `ProcessingJob` 最终应产出 0 或 1 条 `MonitoringRecord`。
- 一个 `MonitoringRecord` 是多个统计读模型的原始来源。
- `data_worker` 负责事件接入、处理与落库。
- `data_server` 负责查询 `MonitoringRecord` 与派生读模型，并对客户端提供稳定业务接口。
- `ViewerUser` 与记录数据没有主从关系，只负责读取和展示。

如果用更简化的表达，可以把主链路理解为：

`Device -> EdgeEventEnvelope -> ProcessingJob / RecognitionResult -> MonitoringRecord -> Read Models -> Client`

## 6. 状态建议

### 6.1 Device 状态

- `online`
- `offline`
- `degraded`

### 6.2 ProcessingJob 状态

- `pending`
- `running`
- `succeeded`
- `retrying`
- `failed`

### 6.3 MonitoringRecord 状态

- `received`
- `normalized`
- `stored`
- `published`
- `failed`

这些状态足够支撑当前阶段的最小业务闭环，不建议一开始就引入更复杂的审核流或人工修订流。

## 7. 当前客户端已实现定义对照

当前 Flutter 客户端里的模型，应该理解为读模型或展示模型，而不是数据库实体。

| 当前模型 | 设计定位 | 说明 |
| --- | --- | --- |
| `AppMode` | 运行模式 | `development` / `no-auth`，不属于业务域 |
| `DashboardSnapshot` | 首页汇总读模型 | 今日识别、今日新增、在线站点、在线设备、最近上传、热点提示 |
| `BirdRecord` | 记录详情/列表读模型 | 当前客户端展示的核心记录视图 |
| `TrendPoint` | 统计聚合点 | 最近一周趋势或日分布 |
| `SpeciesShare` | 统计分布读模型 | 物种占比 |
| `AppUser` | 查看用户模型 | 面向数据展示的普通用户 |

补充说明：

- `accent`、`avatarSeed` 这类字段是纯展示元数据，不是业务核心字段。
- `highlightedBird` 更像首页摘要文案，可以由后端生成，也可以由客户端做展示兜底。
- `capturedAt` 适合保留为展示字符串，但真实业务应以 `captured_at_ms` 作为主时间字段。

## 8. 业务模型与客户端功能的对应关系

当前客户端功能可直接反推为以下业务模型读面：

- 首页：`DashboardSnapshot` + 最近记录摘要 + 热点站点摘要。
- 记录页：`RecordListItem` + 查询条件（站点、时间段、置信度、关键字）。
- 详情页：`RecordDetailView`。
- 统计页：`TrendPoint` + `SpeciesShare` + 时间段聚合结果。
- 我的页：`ViewerUser`。

这意味着未来的业务接口，不需要把 raw event 直接暴露给客户端；客户端只需要稳定的读模型。

### 9. 设计约束

- 不要把边缘上传包和业务记录强行 1:1 对齐。
- 不要把 `Device` 和 `Station` 拆成两个同级业务主实体，当前阶段以 `Device` 统一承载，`Station` 只作为客户端展示标签。
- 不要把用户模型设计成设备管理模型，当前阶段只设计展示用户。
- 不要把展示字段当成持久化主字段，像颜色、头像种子、摘要文案都应该视为展示元数据。
- 不要让未来客户端接口依赖原始边缘 payload 形状，接收端应先完成解析和归一化。

## 10. 结论

当前系统最合理的业务模型可以压缩为四层：

1. `Device`：业务部署单元。
2. `EdgeEventEnvelope` / `ProcessingJob`：接入和处理过程的中间态。
3. `MonitoringRecord`：可持久化的标准业务记录。
4. `data_server` + `DashboardSnapshot` / `RecordDetailView` / `TrendPoint` / `SpeciesShare`：面向客户端的业务接口与读模型出口。

其中，`MonitoringRecord` 是未来最该稳定下来的核心业务实体；`data_worker` 负责把事件沉淀成它，`data_server` 负责围绕它向客户端提供稳定接口，其余模型都应该围绕它派生。
