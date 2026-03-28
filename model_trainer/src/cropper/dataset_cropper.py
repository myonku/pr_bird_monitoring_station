from __future__ import annotations

import json
from pathlib import Path

from PIL import Image

from src.cropper.torch_cropper import PytorchDetectorCropperBackend
from src.cropper.yolo_cropper import YoloDetectorCropperBackend
from src.config import FrameworkKind
from src.models.cropper import CropRunSummary, IMAGE_EXTS


DetectorCropperBackend = YoloDetectorCropperBackend | PytorchDetectorCropperBackend


class DatasetCropper:
    """基于检测模型生成分类训练裁切图的工具模块。"""

    def __init__(
        self,
        backend: DetectorCropperBackend,
        detector_model_path: Path,
        score_threshold: float,
        max_crops_per_image: int,
    ) -> None:
        self.backend = backend
        self.detector_model_path = detector_model_path
        self.score_threshold = score_threshold
        self.max_crops_per_image = max_crops_per_image
        self._detector_handle = backend.load_detector(detector_model_path)

    def run(self, source_root: Path, output_root: Path) -> CropRunSummary:
        source_root = source_root.expanduser().resolve()
        output_root = output_root.expanduser().resolve()
        output_root.mkdir(parents=True, exist_ok=True)

        total_images = 0
        cropped_images = 0
        skipped_images = 0
        manifest: list[dict] = []

        for image_path in sorted(source_root.rglob("*")):
            if image_path.suffix.lower() not in IMAGE_EXTS:
                continue
            total_images += 1

            relative_parent = image_path.parent.relative_to(source_root)
            target_parent = output_root / relative_parent
            target_parent.mkdir(parents=True, exist_ok=True)

            with Image.open(image_path) as image:
                image = image.convert("RGB")
                boxes = self.backend.detect_boxes(
                    image=image, detector_handle=self._detector_handle
                )

                accepted = [box for box in boxes if box.score >= self.score_threshold][
                    : self.max_crops_per_image
                ]

                if not accepted:
                    skipped_images += 1
                    manifest.append(
                        {
                            "source": str(image_path),
                            "crops": [],
                            "status": "no_detection",
                        }
                    )
                    continue

                crop_outputs = []
                width, height = image.size
                for idx, box in enumerate(accepted, start=1):
                    left = int(max(0, min(width - 1, box.x1 * width)))
                    top = int(max(0, min(height - 1, box.y1 * height)))
                    right = int(max(left + 1, min(width, box.x2 * width)))
                    bottom = int(max(top + 1, min(height, box.y2 * height)))

                    cropped = image.crop((left, top, right, bottom))
                    output_path = (
                        target_parent
                        / f"{image_path.stem}_crop{idx}{image_path.suffix}"
                    )
                    cropped.save(output_path)
                    crop_outputs.append(
                        {
                            "path": str(output_path),
                            "score": box.score,
                            "box": {
                                "x1": box.x1,
                                "y1": box.y1,
                                "x2": box.x2,
                                "y2": box.y2,
                            },
                        }
                    )
                    cropped_images += 1

                manifest.append(
                    {
                        "source": str(image_path),
                        "crops": crop_outputs,
                        "status": "ok",
                    }
                )

        manifest_path = output_root / "crop_manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        return CropRunSummary(
            source_root=str(source_root),
            output_root=str(output_root),
            total_images=total_images,
            cropped_images=cropped_images,
            skipped_images=skipped_images,
            manifest_path=str(manifest_path),
        )


def build_cropper_backend(framework: FrameworkKind) -> DetectorCropperBackend:
    if framework == FrameworkKind.YOLO:
        return YoloDetectorCropperBackend()
    if framework == FrameworkKind.PYTORCH:
        return PytorchDetectorCropperBackend()
    raise ValueError(f"unsupported cropper framework: {framework.value}")
