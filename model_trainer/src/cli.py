from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Literal

import numpy as np
import torch
from torch import nn

from src.comparator import compare_summaries
from model_trainer.src.config import TrainConfig
from src.datasets import build_dataloaders
from src.engine import fit
from src.logger import RunLogger
from src.model_factory import SUPPORTED_MODELS, build_model


def _set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)


def _resolve_device(device_option: str) -> str:
    if device_option == "auto":
        return "cuda" if torch.cuda.is_available() else "cpu"
    if device_option == "cuda" and not torch.cuda.is_available():
        raise RuntimeError("CUDA is not available, but --device cuda was requested")
    return device_option


def _train_single(config: TrainConfig) -> Path:
    """根据训练配置训练一个模型，并返回 summary.json 的路径。"""
    _set_seed(config.seed)
    config.models_dir.mkdir(parents=True, exist_ok=True)
    config.logs_dir.mkdir(parents=True, exist_ok=True)

    pin_memory = config.device == "cuda"
    train_loader, val_loader, class_to_idx = build_dataloaders(
        dataset_root=config.dataset_root,
        batch_size=config.batch_size,
        num_workers=config.num_workers,
        image_size=config.image_size,
        pin_memory=pin_memory,
    )

    model = build_model(
        model_name=config.model_name,
        num_classes=len(class_to_idx),
        pretrained=config.pretrained,
    ).to(config.device)

    optimizer = torch.optim.AdamW(
        model.parameters(),
        lr=config.learning_rate,
        weight_decay=config.weight_decay,
    )
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
        optimizer, T_max=config.epochs
    )
    criterion = nn.CrossEntropyLoss()

    logger = RunLogger(
        logs_root=config.logs_dir,
        model_name=config.model_name,
        run_name=config.run_name,
    )
    logger.log_config(config.to_dict())

    checkpoint_dir = config.models_dir / logger.run_id
    results = fit(
        model=model,
        train_loader=train_loader,
        val_loader=val_loader,
        optimizer=optimizer,
        scheduler=scheduler,
        criterion=criterion,
        device=config.device,
        epochs=config.epochs,
        use_amp=config.use_amp,
        checkpoint_dir=checkpoint_dir,
        logger=logger,
    )

    final_val_accuracy = (
        results["history"][-1]["val_accuracy"] if results["history"] else 0.0
    )
    summary = {
        "run_id": logger.run_id,
        "model_name": config.model_name,
        "epochs": config.epochs,
        "num_classes": len(class_to_idx),
        "best_val_accuracy": results["best_val_accuracy"],
        "final_val_accuracy": final_val_accuracy,
        "best_checkpoint": results["best_checkpoint"],
        "last_checkpoint": results["last_checkpoint"],
        "dataset_root": str(config.dataset_root),
        "device": config.device,
    }
    summary_path = logger.log_summary(summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return summary_path


def _build_config(
    args: argparse.Namespace, model_name: Literal["mobilenet_v3", "efficientnet_lite"]
) -> TrainConfig:
    """
    根据命令行参数和模型名称构建训练配置对象。
    """
    device = _resolve_device(args.device)
    use_amp = bool(args.amp and device == "cuda")
    run_name = args.run_name
    if run_name and model_name not in run_name:
        run_name = f"{run_name}_{model_name}"
    return TrainConfig(
        model_name=model_name,
        dataset_root=Path(args.dataset_root),
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        weight_decay=args.weight_decay,
        num_workers=args.num_workers,
        image_size=args.image_size,
        pretrained=args.pretrained,
        device=device,
        use_amp=use_amp,
        seed=args.seed,
        run_name=run_name,
        models_dir=Path(args.models_dir),
        logs_dir=Path(args.logs_dir),
    )


def command_train(args) -> None:
    """训练单个模型（MobileNetV3 或 EfficientNet-Lite）。"""
    config = _build_config(args=args, model_name=args.model)
    _train_single(config=config)


def command_train_both(args) -> None:
    """同时训练 MobileNetV3 和 EfficientNet-Lite，并比较它们的性能。"""
    summaries = []
    for model_name in SUPPORTED_MODELS:
        config = _build_config(args=args, model_name=model_name)
        summary_path = _train_single(config=config)
        summaries.append(summary_path)

    output_csv = Path(args.logs_dir) / "comparison_train_both.csv"
    output_json = Path(args.logs_dir) / "comparison_train_both.json"
    result = compare_summaries(
        summaries, output_csv=output_csv, output_json=output_json
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


def command_compare(args) -> None:
    """比较一个或多个 summary.json 文件，生成排名和统计信息。"""
    summary_paths = [Path(path) for path in args.summaries]
    result = compare_summaries(
        summary_paths=summary_paths,
        output_csv=Path(args.output_csv),
        output_json=Path(args.output_json),
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


def _add_shared_train_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--dataset-root",
        default="dataset",
        help="dataset root containing train/ and test/",
    )
    parser.add_argument("--epochs", type=int, default=20)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--learning-rate", type=float, default=1e-3)
    parser.add_argument("--weight-decay", type=float, default=1e-4)
    parser.add_argument("--num-workers", type=int, default=4)
    parser.add_argument("--image-size", type=int, default=224)
    parser.add_argument(
        "--pretrained", action=argparse.BooleanOptionalAction, default=True
    )
    parser.add_argument("--device", choices=["auto", "cuda", "cpu"], default="auto")
    parser.add_argument("--amp", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--run-name", default=None)
    parser.add_argument("--models-dir", default="models")
    parser.add_argument("--logs-dir", default="logs")


def build_parser() -> argparse.ArgumentParser:
    """
    构建命令行参数解析器，支持多个子命令：train、train-both 和 compare，每个子命令有不同的参数选项。
    """
    parser = argparse.ArgumentParser(description="Bird species classification trainer")
    subparsers = parser.add_subparsers(dest="command", required=True)

    train_parser = subparsers.add_parser("train", help="train one model")
    _add_shared_train_args(train_parser)
    train_parser.add_argument("--model", choices=SUPPORTED_MODELS, required=True)
    train_parser.set_defaults(func=command_train)

    train_both_parser = subparsers.add_parser(
        "train-both", help="train MobileNetV3 and EfficientNet-Lite"
    )
    _add_shared_train_args(train_both_parser)
    train_both_parser.set_defaults(func=command_train_both)

    compare_parser = subparsers.add_parser(
        "compare", help="compare one or more summary.json files"
    )
    compare_parser.add_argument("--summaries", nargs="+", required=True)
    compare_parser.add_argument("--output-csv", default="logs/model_comparison.csv")
    compare_parser.add_argument("--output-json", default="logs/model_comparison.json")
    compare_parser.set_defaults(func=command_compare)

    return parser


def main() -> None:
    """
    命令行入口，根据不同的子命令执行训练或比较操作。
    支持训练单个模型、同时训练两个模型并比较，以及比较已有的 summary.json 文件。
    """
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)

