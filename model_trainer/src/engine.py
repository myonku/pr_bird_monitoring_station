from __future__ import annotations

import contextlib
import time
from pathlib import Path
from typing import Any

import torch
from torch import nn
from torch.amp.grad_scaler import GradScaler

from model_trainer.src.logger import RunLogger


def _accuracy(logits: torch.Tensor, targets: torch.Tensor) -> float:
    predictions = torch.argmax(logits, dim=1)
    correct = (predictions == targets).sum().item()
    return correct / max(1, targets.size(0))


def train_one_epoch(
    model: nn.Module,
    loader: torch.utils.data.DataLoader,
    optimizer: torch.optim.Optimizer,
    criterion: nn.Module,
    device: str,
    use_amp: bool,
) -> dict[str, Any | float]:
    """训练模型一个 epoch，并返回训练损失和准确率。"""
    model.train()
    total_loss = 0.0
    total_correct = 0
    total_count = 0
    scaler = GradScaler("cuda", enabled=use_amp)

    for images, labels in loader:
        images = images.to(device, non_blocking=True)
        labels = labels.to(device, non_blocking=True)

        optimizer.zero_grad(set_to_none=True)
        autocast_context = (
            torch.autocast(device_type="cuda", dtype=torch.float16, enabled=True)
            if use_amp
            else contextlib.nullcontext()
        )
        with autocast_context:
            logits = model(images)
            loss = criterion(logits, labels)

        if use_amp:
            scaler.scale(loss).backward()
            scaler.step(optimizer)
            scaler.update()
        else:
            loss.backward()
            optimizer.step()

        batch_size = labels.size(0)
        total_loss += loss.item() * batch_size
        total_correct += int((logits.argmax(dim=1) == labels).sum().item())
        total_count += batch_size

    return {
        "loss": total_loss / max(1, total_count),
        "accuracy": total_correct / max(1, total_count),
    }


@torch.no_grad()
def evaluate(
    model: nn.Module,
    loader: torch.utils.data.DataLoader,
    criterion: nn.Module,
    device: str,
) -> dict[str, Any | float]:
    """评估模型在验证集上的性能，返回损失和准确率。"""
    model.eval()
    total_loss = 0.0
    total_correct = 0
    total_count = 0

    for images, labels in loader:
        images = images.to(device, non_blocking=True)
        labels = labels.to(device, non_blocking=True)

        logits = model(images)
        loss = criterion(logits, labels)

        batch_size = labels.size(0)
        total_loss += loss.item() * batch_size
        total_correct += int((logits.argmax(dim=1) == labels).sum().item())
        total_count += batch_size

    return {
        "loss": total_loss / max(1, total_count),
        "accuracy": total_correct / max(1, total_count),
    }


def fit(
    model: nn.Module,
    train_loader: torch.utils.data.DataLoader,
    val_loader: torch.utils.data.DataLoader,
    optimizer: torch.optim.Optimizer,
    scheduler: torch.optim.lr_scheduler.CosineAnnealingLR,
    criterion: nn.Module,
    device: str,
    epochs: int,
    use_amp: bool,
    checkpoint_dir: Path,
    logger: RunLogger,
) -> dict[str, Any]:
    """训练模型，并在每个 epoch 结束时评估验证集性能，保存最佳和最后的 checkpoint。"""
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    best_val_acc = -1.0
    best_checkpoint = checkpoint_dir / "best.pt"
    last_checkpoint = checkpoint_dir / "last.pt"
    history = []

    for epoch in range(1, epochs + 1):
        epoch_start = time.time()
        train_metrics = train_one_epoch(
            model=model,
            loader=train_loader,
            optimizer=optimizer,
            criterion=criterion,
            device=device,
            use_amp=use_amp,
        )
        val_metrics = evaluate(
            model=model,
            loader=val_loader,
            criterion=criterion,
            device=device,
        )
        scheduler.step()

        record = {
            "epoch": epoch,
            "train_loss": train_metrics["loss"],
            "train_accuracy": train_metrics["accuracy"],
            "val_loss": val_metrics["loss"],
            "val_accuracy": val_metrics["accuracy"],
            "lr": optimizer.param_groups[0]["lr"],
            "elapsed_sec": time.time() - epoch_start,
        }
        history.append(record)
        logger.log_epoch(record)

        if val_metrics["accuracy"] > best_val_acc:
            best_val_acc = val_metrics["accuracy"]
            torch.save(
                {
                    "epoch": epoch,
                    "model_state_dict": model.state_dict(),
                    "optimizer_state_dict": optimizer.state_dict(),
                    "val_accuracy": best_val_acc,
                },
                best_checkpoint,
            )

        torch.save(
            {
                "epoch": epoch,
                "model_state_dict": model.state_dict(),
                "optimizer_state_dict": optimizer.state_dict(),
                "val_accuracy": val_metrics["accuracy"],
            },
            last_checkpoint,
        )

    return {
        "history": history,
        "best_val_accuracy": best_val_acc,
        "best_checkpoint": str(best_checkpoint),
        "last_checkpoint": str(last_checkpoint),
    }
