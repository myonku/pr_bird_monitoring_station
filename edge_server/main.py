from __future__ import annotations

import argparse
import time
from collections.abc import Iterable

from src.interface import ICaptureModule, ISpoolStorage
from src.models.config import load_edge_config
from src.models.models import CaptureContext, EdgeEvent, ImagePayload
from src.orchestration.decision_engine import DecisionEngine
from src.orchestration.pipeline import EdgePipeline
from src.reasoner.infrencer import LocalModelBundleLoader, TwoStageInferenceModule
from src.uploader.transport_client import HttpTransportClient
from src.uploader.unified_uploader import UnifiedUploader


class DummyCaptureModule(ICaptureModule):
    def __init__(self, device_id: str) -> None:
        self.device_id = device_id

    def wait_and_capture(
        self,
        timeout_sec: float | None = None,
    ) -> tuple[CaptureContext, ImagePayload]:
        if timeout_sec:
            time.sleep(min(timeout_sec, 0.05))

        image_bytes = b"x" * 2048
        context = CaptureContext(device_id=self.device_id, trigger_type="motion")
        image = ImagePayload(
            image_id=f"img-{int(time.time() * 1000)}",
            bytes_data=image_bytes,
            format="jpg",
            width=1920,
            height=1080,
        )
        return context, image


class InMemorySpoolStorage(ISpoolStorage):
    def __init__(self) -> None:
        self._items: dict[str, EdgeEvent] = {}

    def put(self, event: EdgeEvent) -> str:
        self._items[event.event_id] = event
        return event.event_id

    def peek_batch(self, limit: int) -> Iterable[tuple[str, EdgeEvent]]:
        count = 0
        for key, event in self._items.items():
            yield key, event
            count += 1
            if count >= limit:
                break

    def ack(self, record_id: str) -> None:
        self._items.pop(record_id, None)

    def mark_retry(self, record_id: str, reason: str) -> None:
        if record_id in self._items:
            self._items[record_id].metadata["last_retry_reason"] = reason


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Edge server pipeline")
    parser.add_argument("--settings", default="settings.toml")
    parser.add_argument("--loop", action="store_true")
    parser.add_argument("--interval-sec", type=float, default=1.0)
    return parser


def main() -> None:
    args = _build_parser().parse_args()
    cfg = load_edge_config(args.settings)

    capture = DummyCaptureModule(device_id=cfg.runtime.device_id)
    spool = InMemorySpoolStorage()

    model_loader = LocalModelBundleLoader()
    model_loader.load(cfg.model_contract)
    infer = TwoStageInferenceModule()

    transport = HttpTransportClient(
        upload_url=cfg.upload_http.upload_url,
        healthcheck_url=cfg.upload_http.healthcheck_url,
        timeout_sec=cfg.upload_http.timeout_sec,
        auth_token=cfg.upload_http.auth_token or None,
    )
    uploader = UnifiedUploader(transport)

    decision_engine = DecisionEngine(
        confidence_threshold=cfg.decision_policy.confidence_threshold,
        high_load_flag_provider=lambda: cfg.decision_policy.high_load_skip_inference,
    )

    pipeline = EdgePipeline(
        capture=capture,
        model_loader=model_loader,
        infer=infer,
        uploader=uploader,
        spool=spool,
        decision_engine=decision_engine,
    )

    if not args.loop:
        pipeline.run_once()
        print("edge pipeline run_once done")
        return

    while True:
        pipeline.run_once()
        time.sleep(max(args.interval_sec, 0.1))


if __name__ == "__main__":
    main()
