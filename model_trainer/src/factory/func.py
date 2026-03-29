import hashlib


def deterministic_score(seed_text: str, low: float, high: float) -> float:
    """根据输入文本生成一个在 [low, high] 范围内的确定性分数。
    通过对文本进行哈希处理，确保相同输入始终得到相同输出。"""

    digest = hashlib.sha256(seed_text.encode("utf-8")).hexdigest()
    value = int(digest[:8], 16) / 0xFFFFFFFF
    return round(low + (high - low) * value, 4)
