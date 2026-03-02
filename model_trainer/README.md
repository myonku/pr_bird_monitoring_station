# Bird Classification Trainer (CUB_200_2011)

该分区提供了一个可扩展的鸟类识别训练框架，支持：

- `MobileNetV3` 与 `EfficientNet-Lite`（`efficientnet_lite0`）
- 训练 + 验证（验证集使用 `dataset/test`）
- 多模型结果对比导出（CSV/JSON）
- CUDA 优先训练（若可用）

## 数据集目录

默认读取 `dataset/` 下结构：

```text
dataset
├── train
│   ├── class_001
│   ├── class_002
│   └── ...
└── test
	├── class_001
	├── class_002
	└── ...
```

## 代码结构

```text
main.py                     # 统一入口
src/
├── cli.py                 # 命令行入口(train/train-both/compare)
├── config.py              # 训练配置
├── datasets.py            # 自定义 CUB 数据集与 dataloader
├── model_factory.py       # 模型构建（MobileNetV3 / EfficientNet-Lite）
├── engine.py              # 训练/验证引擎
├── logger.py              # 训练日志与 summary 管理
└── comparator.py          # 多模型结果对比
models/                    # 保存 best.pt / last.pt
logs/                      # 保存 config、metrics、summary、comparison
```

## 环境准备（uv）

在 `model_trainer` 目录执行：

```bash
uv sync
```

## 常用命令

1) 训练单模型（自动选择设备，CUDA 可用时默认使用 CUDA）

```bash
uv run python main.py train --model mobilenet_v3 --dataset-root dataset --epochs 30
```

或：

```bash
uv run python main.py train --model efficientnet_lite --dataset-root dataset --epochs 30
```

2) 同时训练两个模型并自动对比

```bash
uv run python main.py train-both --dataset-root dataset --epochs 30
```

3) 对已有 summary 文件做对比

```bash
uv run python main.py compare --summaries logs/run_a/summary.json logs/run_b/summary.json
```

## 输出说明

- 模型：`models/<run_id>/{model_name}_best.pt`、`models/<run_id>/{model_name}_last.pt`
- 训练日志：`logs/<run_id>/metrics.jsonl`
- 运行摘要：`logs/<run_id>/summary.json`
- 双模型对比：`logs/comparison_train_both.csv`、`logs/comparison_train_both.json`
