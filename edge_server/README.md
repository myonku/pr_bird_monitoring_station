# 边缘端识别/上传服务

本分区聚焦边缘业务主流程，认证流程保持隔离：

- 业务数据通道：捕拍 -> 决策 -> （可选）本地推理 -> 事件流上传协调器/本地缓存 -> 网络恢复续传
- 认证通道：独立在 `auth_interface.py` 与 `EDGE_AUTH_DESIGN_SPEC.md` 中定义，不与业务流程耦合

## 工作流程（与当前代码一致）

1. PIR 触发（或 mock 触发）捕拍，得到图像与上下文。
2. 决策模块基于网络状态与设备负载，决定是否本地推理。
3. 若允许本地推理，执行两阶段模型：检测 -> 裁切 -> 分类。
4. 不论是否本地推理，业务上传都经由事件流上传协调器统一封装。
5. 若网络不可用或上传失败，事件写入 SQLite 本地缓存（`data` 分区）。
6. 网络恢复后，`SyncWorker` 批量续传缓存事件。

## 关键代码位置

- 入口编排：`main.py`
- 捕拍编排：`src/ignitor/capture_module.py`
  - `SensorCameraCaptureModule`：sensor + camera 主流程编排
  - `MockCaptureModule`：开发调试模式
  - `PIRCameraCaptureModule`：树莓派模式
- 传感器模块：`src/ignitor/sensor_module.py`
  - `MockMotionSensor` / `PIRMotionSensor`
- 相机模块：`src/ignitor/camera_module.py`
  - `MockCameraController` / `PiCameraController`
- 决策模块：`src/orchestration/decision_engine.py`
- 运行时信号采样（网络/负载）：`src/orchestration/runtime_signal.py`
- 主流水线：`src/orchestration/pipeline.py`
- 本地缓存（SQLite）：
  - `src/local_storage/sqlite_client.py`
  - `src/local_storage/sqlite_spool.py`
- 续传工作器：`src/sync_worker/sync_worker.py`
- 推理编排：`src/reasoner/infrencer.py`
- 推理执行拆分：
  - `src/reasoner/detection_runtime.py`
  - `src/reasoner/classification_runtime.py`
- 模型加载：`src/reasoner/model_loader.py`
- 上传通道：
  - `src/iface/upload_interface.py`
  - `src/transport/event_uploader.py`

## 模型布局（model_pack）

边缘端按目录发现模型，不再依赖旧 `model_contract` 配置块：

- `model_pack/detection`：仅 1 个检测模型
- `model_pack/classification`：仅 1 个分类模型

每个 task 目录必须且仅有一个模型文件，否则启动时失败。

## 本地缓存策略

- 缓存介质：SQLite
- 默认路径：`data/edge_spool.sqlite3`
- 缓存内容：事件元数据 + 推理结果 + 图像二进制
- 续传策略：
  - 仅拉取达到重试时间的记录
  - 失败按指数退避重试（上限封顶）
  - 连续失败达到阈值后直接淘汰（暂不进入死信队列）
- 存储上限策略：
  - 根据磁盘空闲空间动态计算缓存预算
  - 达到容量上限时优先淘汰最旧记录
  - 磁盘空间过低时拒绝新缓存，优先保护系统可用空间

## 配置说明（settings.toml）

配置文件读取策略：仅在入口 `main.py` 读取一次；其他模块仅接收参数或配置对象，不直接读文件。

关键配置段如下：

- `[runtime]`
  - `device_id`
  - `run_mode`: `development` / `no_auth` / `full_development`
  - `spool_db_path`
  - `sync_interval_sec`
  - `sync_batch_size`
- `[auth]`
  - `secret_key_dir`（本地 PEM 密钥目录）
  - `active_key_id`（可选；为空时后端按 `runtime.device_id` 回查公钥）
  - `auth_state_db_path`（认证状态 SQLite 路径）
- `[capture]`
  - `mode`: `mock` / `pir`
  - `pir_gpio_pin`, `pir_wait_timeout_sec`
  - `capture_cooldown_sec`
  - `capture_rate_window_sec`, `capture_rate_max_images`（窗口限频）
  - `image_format`, `image_width`, `image_height`
- `[decision_policy]`
  - `enable_local_inference`
  - `confidence_threshold`
  - `high_load_skip_inference`
  - `cpu_high_watermark`, `memory_high_watermark`
- `[runtime_log]`
  - `enabled`, `include_timestamp`
  - `stages`：按关键节点筛选终端日志（`startup/capture/decision/inference/delivery/sync/auth`）
- `[upload_http]`
  - `base_backend_url`：后端基准地址（scheme + host + port）
  - `upload_path`：事件上传路径
  - `auth_path`：认证通道路径前缀
  - `healthcheck_path`：健康检查路径
  - `timeout_sec`：HTTP 超时控制参数

说明：上传请求的访问令牌由 `EdgeAuthCoordinator` 动态提供，不再从配置读取静态 token。

关键节点日志：

- Pipeline：capture、decision、inference、delivery 各阶段输出简要事件。
- SyncWorker：网络不可用、批次开始、失败记录、批次汇总。
- AuthCoordinator：startup gate、refresh、bootstrap、unauthorized 恢复。
- 可通过 `runtime_log.stages` 精细控制输出粒度，便于部署联调阶段快速定位。

运行模式约束：

- `development`：
  - 不初始化认证模块；
  - 运行时将网络状态固定为不可上传，决策引擎统一走不上传路径；
  - 关闭补传 worker 的对外上传尝试。
- `no_auth`：
  - 初始化认证模块占位实现，但不执行 bootstrap/refresh/鉴权恢复；
  - 对主流程暴露的认证字段全部为空值；
  - 保持业务上传与补传链路可用，用于后端认证未就绪阶段的全流程联调。
- `full_development`：
  - 启动前必须通过认证门禁，确保至少存在可用长期凭证（refresh token）；
  - 若本地不存在可用长期凭证则执行 bootstrap 获取，失败则拒绝启动；
  - 断网场景可继续运行直至长期凭证到期，到期后需恢复网络并重新 bootstrap。
  - 本模式以联调验证认证+业务全链路为目标，不要求在 edge 侧配置 TLS。
- `[model_pack]` + `[[model_pack_lightweight_candidates]]`
  - 模型目录与候选映射

## 树莓派部署提示

- `capture.mode = "pir"` 时需要安装并启用对应硬件依赖（如 `gpiozero`、`picamera2`）。
- `pir_gpio_pin` 使用 BCM GPIO 编号，不是物理针脚号；默认 `17` 表示 GPIO17。
- PIR 输出建议按 3.3V 逻辑接入，并与树莓派共地；当前实现只在输入变为高电平时放行抓拍。
- 未安装硬件依赖时可先用 `capture.mode = "mock"` 完成联调。
- 资源负载采样依赖 `psutil`。

## 运行

- 默认循环执行（推荐，符合边缘端常驻运行模式）：
  - `python main.py --settings settings.toml --interval-sec 1.0`
- 单次执行（仅调试）：
  - `python main.py --settings settings.toml --run-once`