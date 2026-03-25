# model_trainer（多框架/双层级模型训练编排）

本分区已重构为“接口驱动”的训练编排框架，目标是支持：

- 多训练框架并行演进（如 YOLO、PyTorch）
- 统一对比轻量模型与标准模型（对应边缘端与服务端）
- 可插拔数据集适配（当前保留空实现，占位等待数据规范统一）
- 统一产物导出清单（如 ONNX、TFLite、TorchScript）

当前代码重点是“架构与接口”，不是最终训练精度。

说明：边缘端已有 PIR + 红外相机触发链路，训练侧通过检测任务与分类任务候选并行产出模型。
检测阶段用于定位活体目标并过滤背景；分类阶段用于细粒度鸟种识别。

## 设计目标

- 边缘端：优先轻量模型（低延迟、小体积）
- 服务端：优先标准模型（更高精度/鲁棒性）
- 训练侧：同一套流水线同时产出两类模型，并给出可比较指标

## TaskType

- TaskType：描述单个候选模型训练任务（detection 或 classification）
- 两阶段方案由候选组合体现：同一实验中同时配置 detection 与 classification 候选模型即可。

## 当前模块结构

```text
main.py
src/
	cli.py                 # 命令行入口（plan/run/compare）
	config.py              # 统一配置与默认候选模型定义
	logger.py              # 结构化运行日志落盘
	core/
		contracts.py         # 核心接口协议（Evaluator/Exporter/Planner）
		datasets.py          # DatasetAdapter 与占位数据集实现
		model_factory.py     # TrainerBackend 注册与后端实现（YOLO/PyTorch）
		engine.py            # 编排器：执行候选训练并生成结果
		comparator.py        # 排名、分层胜者选择与比较文件导出
```

## 核心接口说明

1. 数据集接口
- `DatasetAdapter.load(contract) -> DatasetBundle`
- 输入：`DatasetContract`（数据集 ID、root、任务类型、元信息）
- 输出：标准化数据集描述（样本统计、类别、元信息）

2. 训练后端接口
- `TrainerBackend.train(candidate, dataset, output_dir) -> TrainingOutput`
- 每个框架（YOLO/PyTorch/Custom）都通过该接口接入

3. 评估接口
- `Evaluator.evaluate(records) -> EvaluationResult`
- 默认评估器支持：
	- 检测任务按 `map50_95` 排序
	- 分类任务按 `top1` 排序
	- 自动选出 `best_lightweight` 与 `best_standard`

4. 模型导出接口（协议预留）
- `ModelExporter.export(candidate_id, checkpoint_path, output_dir) -> list[Path]`
- 用于后续接入真实导出链路（ONNX/TFLite/TensorRT 等）

## 默认候选模型（示例）

`build_default_pipeline_config()` 内置 4 个候选：

- YOLO 轻量检测：`yolo11n`（`lightweight`）
- YOLO 标准检测：`yolo11m`（`standard`）
- PyTorch 轻量分类：`mobilenet_v3_large`（`lightweight`）
- PyTorch 标准分类：`convnext_base`（`standard`）

这只是基线模板，可通过 settings.toml 或外部 config json 覆盖。

## 全局配置文件

全局配置使用 settings.toml，包含：

- [pipeline]：项目名、实验名、输出目录
- [training]：训练通用项（含基础范围校验）
- [deployment]：边缘/服务端的检测与分类模型路径（可手动固定）
- [dataset]：数据集契约占位信息
- [[candidates]]：候选模型与每个候选的 train_params

说明：
- 若 [deployment] 中路径为空字符串，则运行时自动从本次结果中选择最佳模型路径并写入 summary。
- 你现在关心的“检测模型路径”对应：
	- edge_detection_model_path
	- server_detection_model_path

## 命令行

1. 查看有效配置

```bash
uv run python main.py plan --settings settings.toml --dataset-root dataset
```

2. 执行训练编排（当前为接口占位流程，会生成可追踪产物）

```bash
uv run python main.py run --settings settings.toml --dataset-root dataset --dataset-adapter placeholder
```

3. 对比多个运行摘要

```bash
uv run python main.py compare --summaries logs/run_a/summary.json logs/run_b/summary.json
```

## 输出内容

- 运行目录：`logs/<run_id>/`
- 核心文件：
	- `pipeline.json`：本次实验配置快照
	- `summary.json`：所有候选模型结果与比较摘要
	- `summary.json` 中 `deployment_paths`：检测/分类模型路径索引
	- `comparison.csv`：排行榜
	- `comparison.json`：结构化比较结果

模型产物目录：`output_models/<experiment_name>/<candidate_id>/`

## 下一步接入建议

1. 数据集
- 在 `src/core/datasets.py` 实现真实适配器（如 YOLO 标注格式、分类目录格式、统一索引格式）。

2. 真实训练
- 在 `src/core/model_factory.py` 的 `YoloBackend` / `PytorchBackend` 中替换占位逻辑，调用真实训练 API。

3. 协同推理策略
- 在边缘侧消费 `best_lightweight`，在服务端消费 `best_standard`。
- 推理时依据边缘置信度阈值和设备负载决定是否回退到服务端二次推理。
