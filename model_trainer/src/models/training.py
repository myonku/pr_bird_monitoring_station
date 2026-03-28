from dataclasses import dataclass


@dataclass(slots=True)
class TrainingOutput:
    """训练结果的标准化输出格式，包含模型候选信息、性能指标和产物路径。"""
    candidate_id: str
    framework: str
    model_name: str
    tier: str
    task: str
    map50: float
    map50_95: float
    top1: float
    latency_ms: float
    size_mb: float
    checkpoint_path: str
    exported_paths: list[str]
