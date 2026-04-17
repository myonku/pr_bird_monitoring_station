import hashlib
import time
from pathlib import Path
from typing import Any


from src.iface.workflow_interface import IModelBundleLoader
from src.models.workflow.workflow import (
    EdgeModelContract,
    LightweightModelCandidateSpec,
    LoadedModelBundle,
    ModelArtifactContract,
    ModelPackLocator,
)


class LocalModelBundleLoader(IModelBundleLoader):
    """从 model_pack 目录一次加载检测和分类模型，向上层暴露统一模型句柄。"""

    _VALID_MODEL_EXTS = {".onnx", ".pt", ".pth", ".torchscript", ".jit"}
    _VALID_LABEL_EXTS = {".txt", ".names", ".csv", ".labels"}

    def __init__(self) -> None:
        self._bundle: LoadedModelBundle | None = None

    @staticmethod
    def _resolve_runtime_device() -> str:
        try:
            import torch

            return "cuda" if torch.cuda.is_available() else "cpu"
        except Exception:
            return "cpu"

    @staticmethod
    def _build_pytorch_detector(model_name: str, num_classes: int) -> Any:
        from torchvision.models.detection import (
            fasterrcnn_mobilenet_v3_large_320_fpn,
            fasterrcnn_resnet50_fpn,
        )
        from torchvision.models.detection.faster_rcnn import FastRCNNPredictor

        lower = model_name.lower()
        if "mobilenet" in lower:
            model = fasterrcnn_mobilenet_v3_large_320_fpn(weights=None)
        else:
            model = fasterrcnn_resnet50_fpn(weights=None)

        model_any: Any = model
        in_features = int(model_any.roi_heads.box_predictor.cls_score.in_features)
        model_any.roi_heads.box_predictor = FastRCNNPredictor(
            in_features,
            num_classes=num_classes,
        )
        return model

    @staticmethod
    def _build_pytorch_classifier(model_name: str, num_classes: int) -> Any:
        from torch import nn
        from torchvision.models import convnext_base, mobilenet_v3_large

        lower = model_name.lower()
        if "mobilenet" in lower:
            model = mobilenet_v3_large(weights=None)
            model_any: Any = model
            in_features = int(model_any.classifier[-1].in_features)
            model_any.classifier[-1] = nn.Linear(in_features, num_classes)
            return model

        if "convnext" in lower:
            model = convnext_base(weights=None)
            model_any: Any = model
            in_features = int(model_any.classifier[-1].in_features)
            model_any.classifier[-1] = nn.Linear(in_features, num_classes)
            return model

        raise ValueError(f"unsupported pytorch classification model_name: {model_name}")

    @staticmethod
    def _checksum_sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as file:
            for chunk in iter(lambda: file.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _discover_single_model_file(task_dir: Path, task: str) -> Path:
        if not task_dir.exists() or not task_dir.is_dir():
            raise FileNotFoundError(f"{task} model directory not found: {task_dir}")

        candidates = sorted(
            item
            for item in task_dir.rglob("*")
            if item.is_file()
            and item.suffix.lower() in LocalModelBundleLoader._VALID_MODEL_EXTS
        )
        if not candidates:
            raise FileNotFoundError(
                f"no model file found for {task} under: {task_dir}; expected exactly one model"
            )
        if len(candidates) > 1:
            joined = ", ".join(str(item.name) for item in candidates)
            raise ValueError(
                f"expected exactly one model for {task} under {task_dir}, but found {len(candidates)}: {joined}"
            )
        return candidates[0]

    @staticmethod
    def _parse_labels_file(path: Path) -> list[str]:
        labels: list[str] = []
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                label = parts[1].strip()
                if label:
                    labels.append(label)
                continue

            labels.append(parts[0])
        return labels

    @staticmethod
    def _iter_label_file_candidates(label_dir: Path, configured_name: str) -> list[Path]:
        candidates: list[Path] = []
        seen: set[Path] = set()

        def add_candidate(path: Path) -> None:
            resolved = path.resolve()
            if resolved in seen:
                return
            seen.add(resolved)
            candidates.append(path)

        configured_name = configured_name.strip()
        if configured_name:
            add_candidate(label_dir / configured_name)

        for common_name in (
            "labels.txt",
            "class.txt",
            "classes.txt",
            "label.txt",
            "labels.names",
            "class.names",
        ):
            add_candidate(label_dir / common_name)

        if label_dir.exists() and label_dir.is_dir():
            for item in sorted(label_dir.rglob("*")):
                if item.is_file() and item.suffix.lower() in LocalModelBundleLoader._VALID_LABEL_EXTS:
                    add_candidate(item)

        return candidates

    def _resolve_labels_for_task(
        self, locator: ModelPackLocator, task: str
    ) -> list[str]:
        if task == "detection":
            label_file_name = locator.detection_label_file_name.strip()
        else:
            label_file_name = locator.classification_label_file_name.strip()

        label_dir = Path(locator.label_dir)
        candidates = self._iter_label_file_candidates(label_dir, label_file_name)
        for label_path in candidates:
            if not label_path.exists() or not label_path.is_file():
                continue

            try:
                labels = self._parse_labels_file(label_path)
            except (OSError, UnicodeError):
                continue

            if labels:
                return labels

        searched = ", ".join(str(item) for item in candidates) or str(label_dir)
        raise FileNotFoundError(
            f"no usable label file found for task={task} under {label_dir}; searched: {searched}"
        )

    @staticmethod
    def _find_candidate_spec(
        *,
        task: str,
        model_file_name: str,
        candidates: list[LightweightModelCandidateSpec],
    ) -> LightweightModelCandidateSpec:
        matched = [
            item
            for item in candidates
            if item.task == task and item.file_name == model_file_name
        ]
        if not matched:
            expected = sorted(
                item.file_name for item in candidates if item.task == task
            )
            raise ValueError(
                f"no candidate config matched for task={task}, file={model_file_name}; "
                f"expected one of: {expected}"
            )
        if len(matched) > 1:
            raise ValueError(
                f"duplicate candidate configs for task={task}, file={model_file_name}"
            )
        return matched[0]

    def _load_detection_handle(
        self,
        *,
        path: Path,
        spec: LightweightModelCandidateSpec,
        labels: list[str],
    ) -> dict[str, Any]:
        framework = spec.framework.strip().lower()
        if framework == "yolo":
            try:
                from ultralytics import YOLO
            except ImportError as exc:
                raise ModuleNotFoundError(
                    "ultralytics is required for YOLO detection inference. "
                    "Install it with: uv add ultralytics"
                ) from exc

            model = YOLO(str(path))
            return {
                "engine": "yolo",
                "task": "detection",
                "mode": "native",
                "model": model,
                "artifact_path": str(path.resolve()),
                "candidate_id": spec.candidate_id,
                "format": spec.format,
                "framework": spec.framework,
                "model_name": spec.model_name,
                "input_size": spec.input_size,
                "score_threshold": spec.score_threshold,
                "nms_iou_threshold": spec.nms_iou_threshold,
                "topk": spec.topk,
                "labels": labels,
            }

        if framework == "pytorch":
            return self._load_pytorch_detection_handle(
                path=path,
                spec=spec,
                labels=labels,
            )

        raise ValueError(f"unsupported detection framework: {spec.framework}")

    def _load_pytorch_detection_handle(
        self,
        *,
        path: Path,
        spec: LightweightModelCandidateSpec,
        labels: list[str],
    ) -> dict[str, Any]:
        suffix = path.suffix.lower()
        device = self._resolve_runtime_device()

        import torch

        base = {
            "engine": "pytorch",
            "task": "detection",
            "artifact_path": str(path.resolve()),
            "candidate_id": spec.candidate_id,
            "format": spec.format,
            "framework": spec.framework,
            "model_name": spec.model_name,
            "input_size": spec.input_size,
            "score_threshold": spec.score_threshold,
            "nms_iou_threshold": spec.nms_iou_threshold,
            "topk": spec.topk,
            "labels": labels,
            "device": device,
        }

        if suffix == ".pth":
            payload = torch.load(path, map_location=device)
            if not isinstance(payload, dict) or "state_dict" not in payload:
                raise ValueError(f"invalid pytorch detection checkpoint: {path}")

            model_name = str(payload.get("model_name", spec.model_name))
            num_classes = int(payload.get("num_classes", max(2, len(labels))))
            model = self._build_pytorch_detector(model_name, num_classes)
            model.load_state_dict(payload["state_dict"])
            model.to(device)
            model.eval()

            return {
                **base,
                "mode": "eager",
                "model": model,
                "model_name": model_name,
            }

        if suffix in {".torchscript", ".jit", ".pt"}:
            model = torch.jit.load(str(path), map_location=device)
            model.eval()
            return {
                **base,
                "mode": "torchscript",
                "model": model,
            }

        if suffix == ".onnx":
            try:
                import onnxruntime as ort
            except ImportError as exc:
                raise ModuleNotFoundError(
                    "onnxruntime is required for pytorch-onnx detection inference. "
                    "Install it with: uv add onnxruntime"
                ) from exc

            session = ort.InferenceSession(
                str(path),
                providers=["CPUExecutionProvider"],
            )
            input_tensor = session.get_inputs()[0]
            return {
                **base,
                "mode": "onnx",
                "session": session,
                "input_name": input_tensor.name,
                "input_shape": input_tensor.shape,
            }

        raise ValueError(f"unsupported pytorch detection format: {path.suffix}")

    def _load_classification_handle(
        self,
        *,
        path: Path,
        spec: LightweightModelCandidateSpec,
        labels: list[str],
    ) -> dict[str, Any]:
        framework = spec.framework.strip().lower()
        if framework == "yolo":
            try:
                from ultralytics import YOLO
            except ImportError as exc:
                raise ModuleNotFoundError(
                    "ultralytics is required for YOLO classification inference. "
                    "Install it with: uv add ultralytics"
                ) from exc

            model = YOLO(str(path))
            return {
                "engine": "yolo",
                "task": "classification",
                "mode": "native",
                "model": model,
                "artifact_path": str(path.resolve()),
                "candidate_id": spec.candidate_id,
                "format": spec.format,
                "framework": spec.framework,
                "model_name": spec.model_name,
                "input_size": spec.input_size,
                "topk": spec.topk,
                "labels": labels,
            }

        if framework == "pytorch":
            return self._load_pytorch_classification_handle(
                path=path,
                spec=spec,
                labels=labels,
            )

        raise ValueError(f"unsupported classification framework: {spec.framework}")

    def _load_pytorch_classification_handle(
        self,
        *,
        path: Path,
        spec: LightweightModelCandidateSpec,
        labels: list[str],
    ) -> dict[str, Any]:
        suffix = path.suffix.lower()
        device = self._resolve_runtime_device()

        import torch

        base = {
            "engine": "pytorch",
            "task": "classification",
            "artifact_path": str(path.resolve()),
            "candidate_id": spec.candidate_id,
            "format": spec.format,
            "framework": spec.framework,
            "model_name": spec.model_name,
            "input_size": spec.input_size,
            "topk": spec.topk,
            "labels": labels,
            "device": device,
        }

        if suffix == ".pth":
            payload = torch.load(path, map_location=device)
            if not isinstance(payload, dict) or "state_dict" not in payload:
                raise ValueError(f"invalid pytorch classification checkpoint: {path}")

            model_name = str(payload.get("model_name", spec.model_name))
            resolved_labels = list(labels)
            class_names = payload.get("class_names")
            if (
                isinstance(class_names, list)
                and class_names
                and (not resolved_labels or resolved_labels == ["unknown_bird"])
            ):
                resolved_labels = [str(item) for item in class_names]

            num_classes = int(payload.get("num_classes", max(1, len(resolved_labels))))
            model = self._build_pytorch_classifier(model_name, num_classes)
            model.load_state_dict(payload["state_dict"])
            model.to(device)
            model.eval()

            return {
                **base,
                "mode": "eager",
                "model": model,
                "model_name": model_name,
                "labels": resolved_labels,
            }

        if suffix in {".torchscript", ".jit", ".pt"}:
            model = torch.jit.load(str(path), map_location=device)
            model.eval()
            return {
                **base,
                "mode": "torchscript",
                "model": model,
            }

        if suffix == ".onnx":
            try:
                import onnxruntime as ort
            except ImportError as exc:
                raise ModuleNotFoundError(
                    "onnxruntime is required for pytorch-onnx classification inference. "
                    "Install it with: uv add onnxruntime"
                ) from exc

            session = ort.InferenceSession(
                str(path),
                providers=["CPUExecutionProvider"],
            )
            input_tensor = session.get_inputs()[0]
            return {
                **base,
                "mode": "onnx",
                "session": session,
                "input_name": input_tensor.name,
                "input_shape": input_tensor.shape,
            }

        raise ValueError(f"unsupported pytorch classification format: {path.suffix}")

    def _build_artifact(
        self,
        *,
        path: Path,
        spec: LightweightModelCandidateSpec,
        labels: list[str],
    ) -> ModelArtifactContract:
        if not spec.framework:
            raise ValueError(
                f"empty framework in candidate config: {spec.candidate_id}"
            )
        if not spec.model_name:
            raise ValueError(
                f"empty model_name in candidate config: {spec.candidate_id}"
            )

        return ModelArtifactContract(
            artifact_id=path.stem,
            candidate_id=spec.candidate_id,
            task=spec.task,
            tier="lightweight",
            framework=spec.framework,
            model_name=spec.model_name,
            format=spec.format,
            model_version=f"local-{int(path.stat().st_mtime)}",
            artifact_path=str(path.resolve()),
            labels=labels,
            input_size=spec.input_size,
            score_threshold=spec.score_threshold,
            nms_iou_threshold=spec.nms_iou_threshold,
            topk=spec.topk,
            checksum_sha256=self._checksum_sha256(path),
        )

    def load(self, locator: ModelPackLocator) -> LoadedModelBundle:
        if not locator.lightweight_candidates:
            raise ValueError("lightweight_candidates config is empty")

        detection_path = self._discover_single_model_file(
            Path(locator.detection_dir),
            "detection",
        )
        classification_path = self._discover_single_model_file(
            Path(locator.classification_dir),
            "classification",
        )

        detection_spec = self._find_candidate_spec(
            task="detection",
            model_file_name=detection_path.name,
            candidates=locator.lightweight_candidates,
        )
        classification_spec = self._find_candidate_spec(
            task="classification",
            model_file_name=classification_path.name,
            candidates=locator.lightweight_candidates,
        )

        detection_labels = self._resolve_labels_for_task(locator, "detection")
        classification_labels = self._resolve_labels_for_task(locator, "classification")

        detection_handle = self._load_detection_handle(
            path=detection_path,
            spec=detection_spec,
            labels=detection_labels,
        )
        classification_handle = self._load_classification_handle(
            path=classification_path,
            spec=classification_spec,
            labels=classification_labels,
        )

        detection_labels = list(detection_handle.get("labels", detection_labels))
        classification_labels = list(
            classification_handle.get("labels", classification_labels)
        )

        detection = self._build_artifact(
            path=detection_path,
            spec=detection_spec,
            labels=detection_labels,
        )
        classification = self._build_artifact(
            path=classification_path,
            spec=classification_spec,
            labels=classification_labels,
        )

        package_version = f"pack-{int(max(detection_path.stat().st_mtime, classification_path.stat().st_mtime))}"
        contract = EdgeModelContract(
            contract_version="model_pack_runtime_v1",
            package_version=package_version,
            exported_at_ms=int(time.time() * 1000),
            exported_by="edge_server",
            detection=detection,
            classification=classification,
            notes="auto-derived from local model_pack by filename + artifact metadata",
        )

        detection_handle["artifact"] = detection
        classification_handle["artifact"] = classification

        self._bundle = LoadedModelBundle(
            contract=contract,
            detection_handle=detection_handle,
            classification_handle=classification_handle,
        )
        return self._bundle

    def current_bundle(self) -> LoadedModelBundle:
        if self._bundle is None:
            raise RuntimeError("model bundle not loaded")
        return self._bundle

    def current_contract(self) -> EdgeModelContract:
        return self.current_bundle().contract
