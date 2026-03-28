import hashlib
from pathlib import Path

from src.config import ModelCandidate


def deterministic_score(seed_text: str, low: float, high: float) -> float:
    """根据输入文本生成一个在 [low, high] 范围内的确定性分数。
    通过对文本进行哈希处理，确保相同输入始终得到相同输出。"""

    digest = hashlib.sha256(seed_text.encode("utf-8")).hexdigest()
    value = int(digest[:8], 16) / 0xFFFFFFFF
    return round(low + (high - low) * value, 4)


def make_export_artifacts(
    output_dir: Path,
    candidate: ModelCandidate,
    formats: list[str],
) -> list[str]:
    """根据候选模型信息和指定的导出格式，生成占位的导出文件，并返回它们的路径列表。"""

    output_dir.mkdir(parents=True, exist_ok=True)
    prefix = f"{candidate.task.value}_{candidate.tier.value}_{candidate.candidate_id}"
    paths = []
    for item in formats:
        target = output_dir / f"{prefix}.{item}"
        target.write_text(
            (
                "placeholder artifact\n"
                f"framework={candidate.framework.value}\n"
                f"model={candidate.model_name}\n"
                f"tier={candidate.tier.value}\n"
            ),
            encoding="utf-8",
        )
        paths.append(str(target))
    return paths
