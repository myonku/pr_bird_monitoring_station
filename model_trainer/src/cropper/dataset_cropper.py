import json
import shutil
from pathlib import Path
import sys
import time

from PIL import Image

from src.cropper.torch_cropper import PytorchDetectorCropperBackend
from src.cropper.yolo_cropper import YoloDetectorCropperBackend
from src.config import FrameworkKind
from src.datasets.classification_layout import discover_classification_layout
from src.models.cropper import CropBox, CropRunSummary


DetectorCropperBackend = YoloDetectorCropperBackend | PytorchDetectorCropperBackend


class DatasetCropper:
    """基于检测模型生成分类训练裁切图的工具模块。"""

    def __init__(
        self,
        backend: DetectorCropperBackend,
        detector_model_path: Path,
        score_threshold: float,
        max_crops_per_image: int,
        label_file_name: str = "class.txt",
        min_box_area_ratio: float = 0.02,
        max_box_area_ratio: float = 0.90,
        min_box_edge_margin_ratio: float = 0.0,
        max_images_per_class: int = 0,
        padding_ratio: float = 0.0,
        show_progress: bool = True,
        progress_interval: int = 1000,
    ) -> None:
        self.backend = backend
        self.detector_model_path = detector_model_path
        self.score_threshold = score_threshold
        self.max_crops_per_image = max_crops_per_image
        self.label_file_name = label_file_name
        self.min_box_area_ratio = min_box_area_ratio
        self.max_box_area_ratio = max_box_area_ratio
        self.min_box_edge_margin_ratio = min_box_edge_margin_ratio
        self.max_images_per_class = max_images_per_class
        self.padding_ratio = float(max(0.0, float(padding_ratio)))
        self.show_progress = show_progress
        self.progress_interval = max(1, progress_interval)
        self._detector_handle = backend.load_detector(detector_model_path)

    def _is_box_qualified(self, box: CropBox) -> bool:
        x1 = float(max(0.0, min(1.0, box.x1)))
        y1 = float(max(0.0, min(1.0, box.y1)))
        x2 = float(max(0.0, min(1.0, box.x2)))
        y2 = float(max(0.0, min(1.0, box.y2)))

        if x2 <= x1 or y2 <= y1:
            return False

        width_ratio = x2 - x1
        height_ratio = y2 - y1
        area_ratio = width_ratio * height_ratio
        if area_ratio < self.min_box_area_ratio:
            return False
        if area_ratio > self.max_box_area_ratio:
            return False

        margin = self.min_box_edge_margin_ratio
        if margin > 0.0:
            if x1 < margin or y1 < margin or (1.0 - x2) < margin or (1.0 - y2) < margin:
                return False

        return True

    def _print_progress(
        self,
        *,
        processed: int,
        total: int,
        cropped: int,
        skipped: int,
        failed: int,
        start_time: float,
        force: bool = False,
    ) -> None:
        if not self.show_progress:
            return
        if not force:
            if processed <= 0:
                return
            if processed % self.progress_interval != 0 and processed != total:
                return

        elapsed = max(time.perf_counter() - start_time, 1e-6)
        rate = processed / elapsed
        percent = (processed / total * 100.0) if total > 0 else 100.0
        print(
            "[crop] "
            f"{processed}/{total} ({percent:.2f}%) "
            f"cropped={cropped} skipped={skipped} failed={failed} "
            f"rate={rate:.1f} img/s",
            file=sys.stderr,
            flush=True,
        )

    def run(self, source_root: Path, output_root: Path) -> CropRunSummary:
        source_root = source_root.expanduser().resolve()
        output_root = output_root.expanduser().resolve()
        if source_root == output_root:
            raise ValueError("source_root and output_root must be different paths")

        layout = discover_classification_layout(
            source_root,
            label_file_name=self.label_file_name,
        )

        output_root.mkdir(parents=True, exist_ok=True)
        shutil.copy2(layout.class_file, output_root / layout.class_file.name)
        for class_id in layout.classes:
            (output_root / class_id).mkdir(parents=True, exist_ok=True)

        total_images = 0
        cropped_images = 0
        copied_images = 0
        skipped_images = 0
        dropped_no_valid_box_images = 0
        dropped_class_limit_images = 0
        failed_images = 0
        class_output_counts = {class_id: 0 for class_id in layout.classes}

        total_available = len(layout.images)
        start_time = time.perf_counter()
        if self.show_progress:
            print(
                "[crop] start "
                f"total={total_available} "
                f"max_images_per_class={self.max_images_per_class} "
                f"score_threshold={self.score_threshold}",
                file=sys.stderr,
                flush=True,
            )

        manifest_path = output_root / "crop_manifest.json"
        with manifest_path.open("w", encoding="utf-8") as manifest_fp:
            manifest_fp.write("[\n")
            first_record = True

            def write_manifest(record: dict) -> None:
                nonlocal first_record
                if not first_record:
                    manifest_fp.write(",\n")
                manifest_fp.write(json.dumps(record, ensure_ascii=False))
                first_record = False

            for item in layout.images:
                total_images += 1
                image_path = item.image_path

                class_count = class_output_counts.get(item.class_id, 0)
                if (
                    self.max_images_per_class > 0
                    and class_count >= self.max_images_per_class
                ):
                    skipped_images += 1
                    dropped_class_limit_images += 1
                    write_manifest(
                        {
                            "source": str(image_path),
                            "target": None,
                            "class_id": item.class_id,
                            "class_name": item.class_name,
                            "status": "dropped_class_limit_reached",
                            "class_output_count": class_count,
                            "max_images_per_class": self.max_images_per_class,
                        }
                    )
                    self._print_progress(
                        processed=total_images,
                        total=total_available,
                        cropped=cropped_images,
                        skipped=skipped_images,
                        failed=failed_images,
                        start_time=start_time,
                    )
                    continue

                output_path = output_root / item.relative_path

                try:
                    with Image.open(image_path) as image:
                        image = image.convert("RGB")
                        boxes = self.backend.detect_boxes(
                            image=image, detector_handle=self._detector_handle
                        )

                        accepted = [
                            box
                            for box in boxes
                            if box.score >= self.score_threshold
                            and self._is_box_qualified(box)
                        ]
                        accepted = sorted(
                            accepted, key=lambda box: box.score, reverse=True
                        )
                        accepted = accepted[: self.max_crops_per_image]
                        selected = accepted[:1]

                        if not selected:
                            skipped_images += 1
                            dropped_no_valid_box_images += 1
                            write_manifest(
                                {
                                    "source": str(image_path),
                                    "target": None,
                                    "class_id": item.class_id,
                                    "class_name": item.class_name,
                                    "status": "dropped_no_valid_box",
                                    "raw_box_count": len(boxes),
                                    "accepted_box_count": len(accepted),
                                }
                            )
                            self._print_progress(
                                processed=total_images,
                                total=total_available,
                                cropped=cropped_images,
                                skipped=skipped_images,
                                failed=failed_images,
                                start_time=start_time,
                            )
                            continue

                        box = selected[0]
                        width, height = image.size
                        # apply optional padding_ratio around detected box
                        x1f = box.x1 * width
                        y1f = box.y1 * height
                        x2f = box.x2 * width
                        y2f = box.y2 * height

                        box_w = max(1.0, x2f - x1f)
                        box_h = max(1.0, y2f - y1f)
                        pad_w = box_w * self.padding_ratio
                        pad_h = box_h * self.padding_ratio

                        leftf = max(0.0, x1f - pad_w / 2.0)
                        topf = max(0.0, y1f - pad_h / 2.0)
                        rightf = min(float(width), x2f + pad_w / 2.0)
                        bottomf = min(float(height), y2f + pad_h / 2.0)

                        left = int(max(0, min(width - 1, leftf)))
                        top = int(max(0, min(height - 1, topf)))
                        right = int(max(left + 1, min(width, rightf)))
                        bottom = int(max(top + 1, min(height, bottomf)))

                        output_path.parent.mkdir(parents=True, exist_ok=True)
                        cropped = image.crop((left, top, right, bottom))
                        cropped.save(output_path)
                        cropped_images += 1
                        class_output_counts[item.class_id] = class_count + 1

                        write_manifest(
                            {
                                "source": str(image_path),
                                "target": str(output_path),
                                "class_id": item.class_id,
                                "class_name": item.class_name,
                                "status": "cropped",
                                "raw_box_count": len(boxes),
                                "accepted_box_count": len(accepted),
                                "class_output_count": class_output_counts[
                                    item.class_id
                                ],
                                "selected_box": {
                                    "x1": box.x1,
                                    "y1": box.y1,
                                    "x2": box.x2,
                                    "y2": box.y2,
                                    "score": box.score,
                                },
                            }
                        )
                except Exception as exc:
                    failed_images += 1
                    write_manifest(
                        {
                            "source": str(image_path),
                            "target": str(output_path),
                            "class_id": item.class_id,
                            "class_name": item.class_name,
                            "status": "failed",
                            "error": repr(exc),
                        }
                    )

                self._print_progress(
                    processed=total_images,
                    total=total_available,
                    cropped=cropped_images,
                    skipped=skipped_images,
                    failed=failed_images,
                    start_time=start_time,
                )

            manifest_fp.write("\n]\n")

        self._print_progress(
            processed=total_images,
            total=total_available,
            cropped=cropped_images,
            skipped=skipped_images,
            failed=failed_images,
            start_time=start_time,
            force=True,
        )

        return CropRunSummary(
            source_root=str(source_root),
            output_root=str(output_root),
            total_images=total_images,
            cropped_images=cropped_images,
            copied_images=copied_images,
            skipped_images=skipped_images,
            dropped_no_valid_box_images=dropped_no_valid_box_images,
            dropped_class_limit_images=dropped_class_limit_images,
            failed_images=failed_images,
            class_count=len(layout.classes),
            manifest_path=str(manifest_path),
        )


def build_cropper_backend(framework: FrameworkKind) -> DetectorCropperBackend:
    if framework == FrameworkKind.YOLO:
        return YoloDetectorCropperBackend()
    if framework == FrameworkKind.PYTORCH:
        return PytorchDetectorCropperBackend()
    raise ValueError(f"unsupported cropper framework: {framework.value}")
