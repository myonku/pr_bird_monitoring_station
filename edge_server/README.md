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
- 捕拍模块：`src/ignitor/capture_module.py`
  - `MockCaptureModule`：开发调试
  - `PIRCameraCaptureModule`：树莓派模式（PIR + 相机）
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
  - `src/transport/workflow_transport.py`

## 模型布局（model_pack）

边缘端按目录发现模型，不再依赖旧 `model_contract` 配置块：

- `model_pack/detection`：仅 1 个检测模型
- `model_pack/classification`：仅 1 个分类模型

每个 task 目录必须且仅有一个模型文件，否则启动时失败。

## 本地缓存策略

- 缓存介质：SQLite
- 默认路径：`data/edge_spool.sqlite3`
- 缓存内容：事件元数据 + 推理结果 + 图像二进制
- 续传策略：按创建时间顺序批量续传，失败记录重试原因

## 配置说明（settings.toml）

关键配置段如下：

- `[runtime]`
  - `device_id`
  - `spool_db_path`
  - `sync_interval_sec`
  - `sync_batch_size`
- `[capture]`
  - `mode`: `mock` / `pir`
  - `pir_gpio_pin`, `pir_wait_timeout_sec`
  - `capture_cooldown_sec`
  - `image_format`, `image_width`, `image_height`
- `[decision_policy]`
  - `enable_local_inference`
  - `confidence_threshold`
  - `high_load_skip_inference`
  - `cpu_high_watermark`, `memory_high_watermark`
- `[upload_http]`
  - 上传与健康检查地址
- `[model_pack]` + `[[model_pack_lightweight_candidates]]`
  - 模型目录与候选映射

## 树莓派部署提示

- `capture.mode = "pir"` 时需要安装并启用对应硬件依赖（如 `gpiozero`、`picamera2`）。
- 未安装硬件依赖时可先用 `capture.mode = "mock"` 完成联调。
- 资源负载采样依赖 `psutil`。

## 运行

- 单次执行：
  - `python main.py --settings settings.toml`
- 循环执行：
  - `python main.py --settings settings.toml --loop --interval-sec 1.0`