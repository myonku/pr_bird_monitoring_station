# 边缘端业务工作流说明

版本：1.0.0

## 1. 范围

本文档定义鸟类监测运行时的边缘端业务工作流。

在范围内：

- 采集触发与图像接入流程。
- 决策与可选本地推理流程。
- 统一业务上传通道。
- 基于 SQLite 的离线缓冲与断点补传流程。

不在范围内：

- 认证实现细节（见 `EDGE_AUTH_DESIGN_SPEC.md`）；边缘端对外接口清单见 `SYSTEM_EXTERNAL_INTERFACE_CATALOG_DESIGN.md`。
- 模型训练流水线细节。

## 2. 端到端流程

1. 采集阶段：

- 触发源由 `capture.mode` 决定（mock/pir），与 `run_mode` 解耦。
- 抓拍编排在 `SensorCameraCaptureModule` 中完成：先等待 sensor 触发，再调用 camera 抓拍。
- 抓拍进入主流程前先应用最短触发间隔限制，再应用窗口限频（每窗口最多 N 张），超限时阻塞等待。
- 最短触发间隔配置项 `capture_min_trigger_interval_sec` 在代码层最小为 1 秒。
- 窗口限频启用时自适应满足：`capture_rate_window_sec >= capture_min_trigger_interval_sec` 且 `capture_rate_window_sec / capture_rate_max_images >= capture_min_trigger_interval_sec`。
- 采集模块输出 `CaptureContext` 与 `ImagePayload`。

2. 推理前决策阶段：

- 运行时状态采样来源：
- 网络可用性（上传健康检查）
- 设备负载快照（CPU/内存）
- 决策输出：
- 是否执行本地推理
- 是否立即上传
- 是否请求服务端辅助

3. 本地推理阶段（可选）：

- 使用两阶段推理：
- detection -> crop -> classification
- 推理结果与模型签名附加到事件元数据。

4. 投递阶段：

- 业务 payload 始终走单一 HTTP 上传通道。
- 认证流程与业务 pipeline 隔离，不嵌入业务编排逻辑。
- `full_development` 依赖真实认证头；`no_auth` 通过空认证字段直连业务上传；本分区不要求 TLS 配置。

5. 离线缓冲阶段：

- 若策略跳过上传或上传失败，事件写入 SQLite spool。
- spool 数据库默认路径为 `data/edge_spool.sqlite3`。
- spool 写入路径根据磁盘剩余空间动态限制容量。
- 容量超限时优先淘汰最老记录。

6. 恢复补传阶段：

- Sync worker 周期检查连通性并按批次清理待上传记录。
- 上传成功记录 ACK；失败记录标记重试。
- 重试采用指数退避并设置最大退避上限。
- 超过最大重试次数的记录直接淘汰（当前无死信队列）。

## 3. 模块职责

- `main.py`
- 创建具体模块并完成依赖装配。
- 运行主 pipeline 循环与周期性补传。
- `src/ignitor/capture_module.py`
- `SensorCameraCaptureModule`：捕获主流程编排（sensor 与 camera 仅在此交互）。
- `MockCaptureModule`：开发/测试采集源。
- `PIRCameraCaptureModule`：树莓派 PIR 触发抓拍。
- `src/ignitor/sensor_module.py`
- 触发传感器适配层（mock / PIR）。
- `src/ignitor/camera_module.py`
- 相机控制适配层（mock / PiCamera2）。
- `src/orchestration/decision_engine.py`
- 基于运行时状态与推理输出执行策略决策。
- `src/orchestration/runtime_signal.py`
- 采样设备资源并构建运行时状态输入。
- `src/orchestration/pipeline.py`
- 编排单条事件生命周期。
- `src/local_storage/sqlite_spool.py`
- 基于 SQLite 的本地持久化缓冲实现。
- `src/sync_worker/sync_worker.py`
- 负责从 spool 断点补传。
- `src/reasoner/*`
- 模型加载与推理执行。
- `src/transport/*`
- 统一业务上传传输层。

## 4. 数据通道隔离

业务通道与认证通道必须隔离：

- 业务模块只调用 uploader 接口。
- 认证模型与接口保持在认证子模块下。
- 边缘业务 pipeline 中不嵌入认证编排逻辑。
- 业务 uploader 必须消费认证模块输出的认证头；认证不可用时先走认证恢复（refresh/bootstrap）再上传。

## 5. 配置基线

`settings.toml` 预期关键配置段：

- `[runtime]`
- `runtime.run_mode`: `development` / `no_auth` / `full_development`
- `[capture]`
- `capture_min_trigger_interval_sec`, `capture_rate_window_sec`, `capture_rate_max_images`
- `[decision_policy]`
- `[upload_http]`
- `[runtime_log]`
- `[model_pack]`
- `[[model_pack_lightweight_candidates]]`

### 5.2 运行日志观测

- 通过 `runtime_log` 配置控制关键节点终端打印。
- 推荐至少开启：`startup`、`capture`、`delivery`、`sync`，便于部署初期观测端到端是否打通。
- 若终端噪音过高，可仅保留 `startup` + `delivery` + `auth`。

## 5.1 运行模式协同约束

- `development` 模式：

  - 不初始化认证模块；
  - 决策输入中的 `network_ready` 固定为 `false`，由决策引擎统一决定不上传；
  - 本地推理与落盘逻辑保持正常；
  - 不执行补传 worker 的对外上传尝试。
- `no_auth` 模式：

  - 初始化无认证占位协调器，但不执行 bootstrap/refresh/未授权恢复；
  - 对业务上传暴露的认证字段全部为空值；
  - 保持实时上传与断点补传链路可用。
- `full_development` 模式：

  - 启动前必须通过认证门禁，至少持有可用长期凭证（refresh token）；
  - 若长期凭证缺失/过期，则在启动阶段执行 bootstrap 重新获取；
  - 断网时可继续本地流程直至长期凭证到期；到期后需恢复联网并重新 bootstrap 才可继续主流程。
  - 本模式不在边缘端配置层面约束 TLS，用于认证+业务链路联调。

## 6. 演进规则

1. 保持 pipeline 步骤显式且单向。
2. 保持推理与非推理事件共用统一投递路径。
3. 保持离线持久化本地化且可确定（优先 SQLite）。
4. 保持认证集成以独立接口方式可插拔。
5. 新增采集/推理后端应通过适配层扩展，避免膨胀 orchestration 模块。
