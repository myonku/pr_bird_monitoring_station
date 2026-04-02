from dataclasses import dataclass
from pathlib import Path

from src.models.dataset_model import ClassificationImageItem, ClassificationLayout
from src.models.common import IMAGE_EXTENSIONS


def discover_classification_layout(
    root: Path,
    label_file_name: str = "class.txt",
) -> ClassificationLayout:
    root = root.expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"classification dataset root not found: {root}")

    normalized_label_file_name = label_file_name.strip()
    if not normalized_label_file_name:
        raise ValueError("label_file_name must not be empty")

    if Path(normalized_label_file_name).name != normalized_label_file_name:
        raise ValueError(
            "label_file_name must be a file name without directory separators"
        )

    class_file = root / normalized_label_file_name
    if not class_file.exists():
        raise FileNotFoundError(
            "classification label file not found: "
            f"{class_file} (configured as '{normalized_label_file_name}')"
        )

    classes = _parse_class_file(class_file)
    if not classes:
        raise ValueError(f"classification class file is empty: {class_file}")

    images: list[ClassificationImageItem] = []
    class_image_counts: dict[str, int] = {}

    for class_id, class_name in classes.items():
        class_dir = root / class_id
        if not class_dir.is_dir():
            raise FileNotFoundError(
                f"classification class directory not found for {class_id}: {class_dir}"
            )

        count = 0
        for image_path in sorted(class_dir.rglob("*")):
            if image_path.suffix.lower() not in IMAGE_EXTENSIONS:
                continue
            count += 1
            images.append(
                ClassificationImageItem(
                    class_id=class_id,
                    class_name=class_name,
                    image_path=image_path,
                    relative_path=image_path.relative_to(root),
                )
            )

        class_image_counts[class_id] = count

    if not images:
        raise ValueError(
            f"no image files found under classification dataset root: {root}"
        )

    extra_top_level_dirs = sorted(
        item.name
        for item in root.iterdir()
        if item.is_dir() and item.name not in classes
    )

    return ClassificationLayout(
        root=root,
        class_file=class_file,
        classes=classes,
        images=images,
        class_image_counts=class_image_counts,
        extra_top_level_dirs=extra_top_level_dirs,
    )


def _parse_class_file(class_file: Path) -> dict[str, str]:
    classes: dict[str, str] = {}
    for line_no, raw_line in enumerate(
        class_file.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            raise ValueError(
                "invalid label file line format at "
                f"{class_file}:{line_no}, expected '<class_id> <class_name>'"
            )

        class_id, class_name = parts[0].strip(), parts[1].strip()
        if not class_id:
            raise ValueError(f"invalid empty class id at {class_file}:{line_no}")
        if not class_name:
            raise ValueError(f"invalid empty class name at {class_file}:{line_no}")
        if class_id in classes:
            raise ValueError(
                f"duplicate class id '{class_id}' in label file at line {line_no}"
            )

        classes[class_id] = class_name
    return classes
