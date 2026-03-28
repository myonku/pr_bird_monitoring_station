from dataclasses import dataclass


IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".bmp", ".webp"}


@dataclass(slots=True)
class CropBox:
    """表示检测到的目标边界框及其置信度。"""
    x1: float
    y1: float
    x2: float
    y2: float
    score: float


@dataclass(slots=True)
class CropRunSummary:
    """裁切运行的总结信息，包括输入输出路径、处理的图片数量、
    裁切成功与跳过的统计，以及生成的清单文件路径。"""
    source_root: str
    output_root: str
    total_images: int
    cropped_images: int
    skipped_images: int
    manifest_path: str
