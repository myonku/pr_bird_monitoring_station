from __future__ import annotations

import csv
import json
from pathlib import Path


def _load_summary(path: Path) -> dict:
    content = path.read_text(encoding="utf-8")
    payload = json.loads(content)
    payload["summary_path"] = str(path)
    return payload


def compare_summaries(
    summary_paths: list[Path], output_csv: Path, output_json: Path
) -> dict:
    """比较多个 summary.json 文件，生成排名和统计信息，并将结果保存为 CSV 和 JSON 格式。"""
    rows = []
    for summary_path in summary_paths:
        summary = _load_summary(summary_path)
        rows.append(
            {
                "model": summary.get("model_name"),
                "run_id": summary.get("run_id"),
                "best_val_accuracy": summary.get("best_val_accuracy"),
                "final_val_accuracy": summary.get("final_val_accuracy"),
                "epochs": summary.get("epochs"),
                "best_checkpoint": summary.get("best_checkpoint"),
                "summary_path": summary.get("summary_path"),
            }
        )

    rows.sort(key=lambda item: item["best_val_accuracy"], reverse=True)
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    output_json.parent.mkdir(parents=True, exist_ok=True)

    with output_csv.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    comparison = {
        "winner": rows[0]["model"],
        "winner_best_val_accuracy": rows[0]["best_val_accuracy"],
        "rows": rows,
    }
    output_json.write_text(
        json.dumps(comparison, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return comparison
