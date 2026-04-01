import io
from typing import Any

from PIL import Image

from src.models.models import ImagePayload, ModelArtifactContract


def safe_label(labels: list[str], index: int, prefix: str) -> str:
    if 0 <= index < len(labels):
        return labels[index]
    return f"{prefix}_{index}"


def normalize_input_size(
    input_size: Any,
    default: tuple[int, int],
) -> tuple[int, int]:
    if isinstance(input_size, (tuple, list)) and len(input_size) == 2:
        return int(input_size[0]), int(input_size[1])
    if isinstance(input_size, (int, float, str)):
        value = int(input_size)
        return value, value
    return default


def load_rgb(image: ImagePayload) -> Image.Image:
    with Image.open(io.BytesIO(image.bytes_data)) as raw:
        return raw.convert("RGB")


def build_model_signature(
    handle: dict[str, Any],
    artifact: ModelArtifactContract,
) -> str:
    candidate_id = str(
        handle.get("candidate_id") or artifact.candidate_id or "unknown_candidate"
    )
    model_name = str(handle.get("model_name") or artifact.model_name or "unknown_model")
    model_format = str(handle.get("format") or artifact.format or "unknown_format")
    return f"{candidate_id}|{model_name}|{model_format}"
