# model_trainer（手动单模型训练与产物记录）

本分区当前目标是手动配置并执行单模型训练，核心能力：

- 多训练框架并行演进（如 YOLO、PyTorch）
- 按 `task+tier` 手动选择单次训练模型
- 检测任务与分类任务都使用真实数据适配与真实训练流程
- 自动记录本次摘要，并和上一次同 lane 训练做对比

当前代码重点是“稳定可追溯的单次训练流程”，不是最终训练精度。

说明：边缘端已有 PIR + 红外相机触发链路，训练侧通过检测任务与分类任务候选并行产出模型。
检测阶段用于定位活体目标并过滤背景；分类阶段用于细粒度鸟种识别。

当前流程已调整为：

- 先用公开检测数据训练检测模型（标签统一归并为 bird）。
- 再用检测模型对自有分类数据做目标裁切。
- 使用裁切后的分类数据训练分类模型。

检测数据集已支持 CUB 转换后的统一结构（bird_detection_dataset）：

- images/{train,val,test}
- labels/{train,val,test}
- annotations/instances_{train,val,test}.json
- yolo.yaml

## 设计目标

- 边缘端：优先轻量模型（低延迟、小体积）
- 服务端：优先标准模型（更高精度/鲁棒性）
- 训练侧：同一套流水线同时产出两类模型，并给出可比较指标

## TaskType

- TaskType：描述单个候选模型训练任务（detection 或 classification）。
- `run` 命令现在强制指定 `--task` + `--tier`，一次只执行一个模型基线。
- 候选模型固定为 4 个组合：
- detection x lightweight
- detection x standard
- classification x lightweight
- classification x standard
- 每次运行只会命中上述组合中的一个候选，因此每次仅产生一份模型产物。

## 当前模块结构

```text
main.py
src/
	cli.py                 # 命令行入口（plan/run/crop-dataset/export-model）
	config.py              # 统一配置与默认候选模型定义
	logger.py              # 结构化运行日志落盘
	datasets/
		datasets.py              # 数据集服务路由（unified / bird-classification / auto）
		detection_dataset.py     # CUB det_bird 检测数据适配
		classification_dataset.py# 分类数据适配（真实目录解析）
	factory/
		model_factory.py           # 训练后端注册（YOLO/PyTorch）
		torch_backend.py
		yolo_backend.py
	cropper/
		dataset_cropper.py       # 基于检测模型生成分类裁切
		yolo_cropper.py          # YOLO 裁切后端
		torch_cropper.py         # PyTorch 裁切后端
	evaluator/
		comparator.py            # 排名与结果导出
	models/
		common.py                # 公共枚举与常量
		dataset_model.py         # DatasetBundle
		cropper.py               # CropBox/CropRunSummary
	engine.py                  # 编排器：执行候选训练并生成结果
```

## 核心组件说明

1. 数据集服务

- `DatasetService.load(contract) -> DatasetBundle`
- 检测任务固定走真实检测适配器（`UnifiedBirdDetectionDatasetAdapter`），不再支持占位数据集。
- 分类任务在 `auto` 模式下走真实分类适配器（`BirdClassificationDatasetAdapter`），不再支持占位数据集。

2. 训练后端

- 检测任务：`YoloBackend` 与 `PytorchBackend` 均已接入真实训练流程。
- 分类任务：`YoloBackend` 与 `PytorchBackend` 均已接入真实训练流程。

3. 结果比较

- 由 `src/core/evaluator/comparator.py` 直接对结果排序。
- 检测任务按 `map50_95`，分类任务按 `top1`。
- 单次运行只包含一个候选，`comparison` 字段用于统一记录本次指标。
- 每次 `run` 完成后会自动与同 lane 的上一次 `summary.json` 对比。
- 对比时间线会追加到 `logs/<lane>/summary_compare_timeline.jsonl`。

4. 裁切生成

- `crop-dataset` 命令要求 `--tier`，先在 `logs/<lane>` 中按 `map50_95` 排序选择检测模型（仅搜索前 `max_selection_candidates` 个候选）。
- 若自动选模失败，会回退到 `[crop_generation]` 的 `framework + detector_model_path`；回退路径也无效时命令退出。
- 裁切阶段不会再复制原图兜底：低置信度或未通过框质量约束的图片会直接丢弃。
- 支持按类别限制成品数量：`max_images_per_class` 可限制每个 class_id 最终输出上限（例如每类最多 5000 张）。
- 裁切输出保持分类目录结构不变，并生成 `crop_manifest.json`（状态包含 `cropped`、`dropped_no_valid_box`、`dropped_class_limit_reached`、`failed`）。
- 支持简单进度显示（stderr）：通过 `show_progress` 和 `progress_interval` 配置。

5. 模型导出

- `export-model` 命令按 `task + tier` 从 `logs/<lane>` 读取历史 `summary.json`，按任务指标排序后仅在前 `max_selection_candidates` 个候选中选模。
- 排序指标与裁切选模一致：检测按 `map50_95`，分类按 `top1`。
- 导出时会将选中的模型文件复制到 `--output` 指定目录，并输出选中来源与元信息（`source=logs_topk`）。

## 默认候选模型（示例）

`build_default_pipeline_config()` 内置 4 个候选：

- YOLO 轻量检测：`yolo11n`（`lightweight`）
- YOLO 标准检测：`yolo11m`（`standard`）
- PyTorch 轻量分类：`mobilenet_v3_large`（`lightweight`）
- PyTorch 标准分类：`convnext_base`（`standard`）

这只是基线模板，可通过 settings.toml 或外部 config json 覆盖。

## 全局配置文件

全局配置使用 settings.toml，包含：

- [pipeline]：输出目录根路径
- [training]：训练通用项（含基础范围校验）
- [dataset]：数据集契约基础信息（如需扩展）
- [detection_dataset]：检测训练数据集（位置标注，标签可归并）
- [classification_dataset]：分类训练数据集（裁切后，仅类别标签）
- [crop_generation]：裁切任务配置（回退模型、标签文件名、输入输出路径、阈值、自动选模候选上限、框质量过滤、每类数量上限、进度显示）
- [[candidates]]：候选模型与每个候选的 train_params

说明：

- 运行时按 `--task + --tier` 只选择一个候选执行。
- 建议固定保留四个候选并仅替换模型名/参数，不新增组合。

## 命令行

1. 查看有效配置

```bash
uv run python main.py plan --settings settings.toml
```

2. 执行单次训练（四类组合，直接可复制）

```bash
uv run python main.py run --settings settings.toml --task detection --tier lightweight --dataset-adapter auto
```

```bash
uv run python main.py run --settings settings.toml --task detection --tier standard --dataset-adapter auto
```

```bash
uv run python main.py run --settings settings.toml --task classification --tier lightweight --dataset-adapter auto
```

```bash
uv run python main.py run --settings settings.toml --task classification --tier standard --dataset-adapter auto
```

3. 生成分类裁切数据集

```bash
uv run python main.py crop-dataset --settings settings.toml --tier <lightweight|standard>
```

4. 导出指定训练类型的模型产物

```bash
uv run python main.py export-model --settings settings.toml --task <detection|classification> --tier <lightweight|standard> --max-selection-candidates <N> --output <target_dir>
```

说明：

- `--max-selection-candidates`（或 `--max_selection_candidates`）用于限制仅在日志排序前 N 个候选中寻找可用模型文件。

命令输出中的 `selected_model.source` 含义：

- `logs_topk`：来自日志自动选模（按评分排序并受 top-N 限制）。
- `crop_generation_fallback`：日志选模失败后使用配置回退模型。

## 输出内容

- lane 目录：
  - `detection_lite`
  - `detection_std`
  - `classification_lite`
  - `classification_std`
- 日志目录：`logs/<lane>/<run_id>/`
- 核心文件：
  - `pipeline.json`：本次运行配置快照
    - `summary.json`：单模型训练结果与摘要
    - `comparison.csv`：本次摘要对比表（单候选）
  - `comparison.json`：当前任务本次结构化比较结果
    - `comparison_with_previous.csv/json`：自动生成的“本次 vs 上次同 lane”对比（首跑无此文件）
    - `logs/<lane>/summary_compare_timeline.jsonl`：同 lane 历次训练对比时间线

模型产物目录：`output_models/<lane>/<run_id>/`
产物文件直接落在 run_id 目录下，文件名内嵌 task/tier/candidate 标签，不再使用多级实验目录。

## 下一步接入建议

1. 数据集与训练质量

- 分类数据与训练流程已真实化；后续可补充更严格的数据质量校验（如坏图检测、类间样本不均衡告警）。

2. 推理侧接入

- 按 lane 选择对应的最新 run 目录产物（如 `detection_lite` 或 `classification_std`）。
- 线上切换建议通过外部发布清单管理，不依赖训练端自动挑选最佳模型。
