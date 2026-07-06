from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

from src.iface.agent.tools import ITool
from src.models.agent.schemas import (
    AgentRequest,
    ImageRef,
    ToolCall,
    ToolError,
    ToolResult,
    ToolStatus,
)
from src.models.inference.workflow import (
    InferenceImagePayload,
    TwoStageInferenceResult,
)
from src.models.sys.config import ProjectConfig
from src.modules.inference.inference_module import (
    TwoStageInferenceModule,
    build_standard_inference_module,
)
from src.modules.inference.speices_resolver import SpeciesResolver

MIN_CLASSIFICATION_CONFIDENCE = 0.8
MAX_IMAGES = 3


class ImageInferenceTool(ITool):
    """图片鸟类识别工具。

    接收 ProjectConfig 以获取推理引擎配置和可选的 MySQL 连接配置，
    运行时从 AgentRequest.images 中提取图片数据执行推理。
    """

    name = "image_inference_tool"
    description = "图片识别：检测图片中是否有鸟类并识别物种"

    def __init__(
        self,
        config: ProjectConfig,
        *,
        base_dir: str | Path = ".",
        enable_species_resolver: bool = True,
        min_confidence: float = MIN_CLASSIFICATION_CONFIDENCE,
    ) -> None:
        if config is None:
            raise ValueError("config is required")

        self._config = config
        self._base_dir = Path(base_dir).resolve()
        self._enable_species = enable_species_resolver
        self._min_confidence = max(0.0, min(1.0, float(min_confidence)))

        # 在首次 execute 时懒初始化
        self._inference: TwoStageInferenceModule | None = None
        self._species_resolver: SpeciesResolver | None = None
        self._initialized = False

    async def execute(self, call: ToolCall, req: AgentRequest) -> ToolResult:
        start = time.time()

        try:
            await self._ensure_initialized()
        except Exception as exc:
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.ERROR,
                error=ToolError(
                    code="INIT_FAILED",
                    message=f"tool initialization failed: {exc}",
                ),
                latency_ms=int((time.time() - start) * 1000),
            )

        images = list((req.images or [])[:MAX_IMAGES])
        if not images:
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.ERROR,
                error=ToolError(
                    code="NO_IMAGES",
                    message="no images found in request",
                ),
                latency_ms=int((time.time() - start) * 1000),
            )

        results: list[dict[str, Any]] = []
        has_any_detection = False

        for img in images:
            payload = _build_inference_payload(img)
            item = await self._infer_single_image(payload)
            if item["detected"]:
                has_any_detection = True
            results.append(item)

        return ToolResult(
            tool_name=self.name,
            status=ToolStatus.OK,
            payload={
                "has_detection": has_any_detection,
                "total_images": len(images),
                "detected_count": sum(1 for r in results if r["detected"]),
                "results": results,
            },
            latency_ms=int((time.time() - start) * 1000),
        )

    async def _ensure_initialized(self) -> None:
        if self._initialized:
            return

        inference_cfg = self._config.inference
        if inference_cfg is not None:
            normalized = inference_cfg.normalized(base_dir=self._base_dir)
            self._inference = await asyncio.to_thread(
                build_standard_inference_module, normalized
            )

        self._initialized = True

    async def _infer_single_image(
        self,
        payload: InferenceImagePayload,
    ) -> dict[str, Any]:
        if self._inference is None:
            return {
                "image_id": payload.image_id,
                "detected": False,
                "reason": "inference_engine_unavailable",
            }

        try:
            result: TwoStageInferenceResult = await asyncio.to_thread(
                self._inference.infer_two_stage, payload
            )
        except Exception as exc:
            return {
                "image_id": payload.image_id,
                "detected": False,
                "reason": f"inference_error:{exc}",
            }

        # 判断两阶段推理是否走通
        classified_ok = (
            result.success
            and result.stage == "classified"
            and result.classification is not None
            and result.classification.success
        )

        item: dict[str, Any] = {
            "image_id": payload.image_id,
            "detected": False,
            "stage": result.stage,
            "reason": result.reason,
        }

        if classified_ok and result.classification is not None:
            label = (result.classification.top1_label or "").strip()
            confidence = float(result.classification.top1_confidence or 0.0)

            item["label"] = label
            item["confidence"] = confidence

            # top1 置信度低于阈值 → 训练数据中无该种别，判定为未识别
            if confidence < self._min_confidence:
                item["reason"] = "classification_confidence_too_low"
            else:
                item["detected"] = True
                # 如果 SpeciesResolver 可用，补充物种详情
                if label and self._species_resolver is not None and self._enable_species:
                    item["species"] = await self._resolve_species(label)

        return item

    async def _resolve_species(self, label: str) -> dict[str, str] | None:
        resolver = self._species_resolver
        if resolver is None:
            return None

        try:
            profile = await resolver.resolve_by_label(label)
        except Exception:
            return None

        if profile is None:
            return None

        return {
            "species_entity_id": str(profile.species_entity_id),
            "scientific_name": profile.scientific_name,
            "display_name": profile.display_name,
            "intro": profile.intro,
            "habitat": profile.habitat,
            "protection_level": profile.protection_level,
        }

def _build_inference_payload(img: ImageRef) -> InferenceImagePayload:
    """将 AgentRequest 中的 ImageRef 转换为推理引擎所需的载荷。"""
    mime = (img.mime_type or "").lower()
    if "png" in mime:
        fmt = "png"
    elif "webp" in mime:
        fmt = "webp"
    else:
        fmt = "jpeg"

    return InferenceImagePayload(
        image_id=img.image_id or f"img_{int(time.time() * 1000)}",
        bytes_data=img.data,
        format=fmt,
    )
