from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


def _primary_score(item: dict[str, Any]) -> float:
    if item.get("task") == "detection":
        return float(item.get("map50_95", 0.0) or 0.0)
    return float(item.get("top1", 0.0) or 0.0)


def compare_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    ranked = sorted(records, key=_primary_score, reverse=True)

    best_lightweight = next(
        (item for item in ranked if item.get("tier") == "lightweight"), None
    )
    best_standard = next(
        (item for item in ranked if item.get("tier") == "standard"), None
    )

    return {
        "leaderboard": ranked,
        "best_lightweight": best_lightweight,
        "best_standard": best_standard,
        "overall_winner": ranked[0] if ranked else None,
    }


def compare_summary_files(summary_paths: list[Path]) -> dict[str, Any]:
    all_records: list[dict[str, Any]] = []
    for path in summary_paths:
        payload = json.loads(path.read_text(encoding="utf-8"))
        for item in payload.get("results", []):
            copied = dict(item)
            copied["source_summary"] = str(path)
            all_records.append(copied)
    return compare_records(all_records)


def save_comparison(
    comparison: dict[str, Any],
    output_csv: Path,
    output_json: Path,
) -> None:
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    output_json.parent.mkdir(parents=True, exist_ok=True)

    leaderboard = comparison.get("leaderboard", [])
    if leaderboard:
        with output_csv.open("w", encoding="utf-8", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=list(leaderboard[0].keys()))
            writer.writeheader()
            writer.writerows(leaderboard)

    output_json.write_text(
        json.dumps(comparison, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
