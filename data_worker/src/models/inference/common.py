from enum import StrEnum
from typing import Literal


ArtifactFormat = Literal["onnx", "tflite", "torchscript", "openvino", "custom"]


class ModelTier(StrEnum):
    LIGHTWEIGHT = "lightweight"
    STANDARD = "standard"


class FrameworkKind(StrEnum):
    YOLO = "yolo"
    PYTORCH = "pytorch"
    CUSTOM = "custom"


class TaskType(StrEnum):
    DETECTION = "detection"
    CLASSIFICATION = "classification"


class LabelPolicy(StrEnum):
    AS_IS = "as_is"
    SINGLE_CLASS_BIRD = "single_class_bird"
    SPECIES_CLASSIFICATION = "species_classification"


def lane_key(task: TaskType, tier: ModelTier) -> str:
    mapping = {
        (TaskType.DETECTION, ModelTier.LIGHTWEIGHT): "detection_lite",
        (TaskType.DETECTION, ModelTier.STANDARD): "detection_std",
        (TaskType.CLASSIFICATION, ModelTier.LIGHTWEIGHT): "classification_lite",
        (TaskType.CLASSIFICATION, ModelTier.STANDARD): "classification_std",
    }
    return mapping[(task, tier)]