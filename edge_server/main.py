import argparse
import time
import tomllib
from pathlib import Path

from src.ignitor.func import build_capture_module
from src.models.sys.func import load_edge_config
from src.orchestration.decision_engine import DecisionEngine
from src.orchestration.pipeline import EdgePipeline
from src.orchestration.runtime_signal import ResourceMonitor
from src.models.workflow.runtime import RuntimeStatus
from src.local_storage.sqlite_spool import SQLiteSpoolStorage
from src.sync_worker.sync_worker import SyncWorker
from src.reasoner.infrencer import TwoStageInferenceModule
from src.reasoner.model_loader import LocalModelBundleLoader
from src.transport.event_uploader import EdgeEventHttpUploadCoordinator


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Edge server pipeline")
    parser.add_argument("--settings", default="settings.toml")
    parser.add_argument("--loop", action="store_true")
    parser.add_argument("--interval-sec", type=float, default=1.0)
    return parser


def main() -> None:
    args = _build_parser().parse_args()
    settings_path = Path(args.settings).resolve()
    with settings_path.open("rb") as file:
        raw_settings = tomllib.load(file)
    cfg = load_edge_config(raw_settings, base_dir=settings_path.parent)

    capture = build_capture_module(cfg.capture, cfg.runtime.device_id)
    spool = SQLiteSpoolStorage(cfg.runtime.spool_db_path)

    model_loader = LocalModelBundleLoader()
    model_loader.load(cfg.model_pack)
    infer = TwoStageInferenceModule()

    pipeline_uploader = EdgeEventHttpUploadCoordinator(
        upload_url=cfg.upload_http.upload_url,
        healthcheck_url=cfg.upload_http.healthcheck_url,
        timeout_sec=cfg.upload_http.timeout_sec,
        auth_token=cfg.upload_http.auth_token or None,
    )
    sync_uploader = EdgeEventHttpUploadCoordinator(
        upload_url=cfg.upload_http.upload_url,
        healthcheck_url=cfg.upload_http.healthcheck_url,
        timeout_sec=cfg.upload_http.timeout_sec,
        auth_token=cfg.upload_http.auth_token or None,
    )

    resource_monitor = ResourceMonitor(
        cpu_high_watermark=cfg.decision_policy.cpu_high_watermark,
        memory_high_watermark=cfg.decision_policy.memory_high_watermark,
        force_high_load=cfg.decision_policy.high_load_skip_inference,
    )

    decision_engine = DecisionEngine(
        enable_local_inference=cfg.decision_policy.enable_local_inference,
        confidence_threshold=cfg.decision_policy.confidence_threshold,
    )

    def runtime_status_provider() -> RuntimeStatus:
        """采样当前设备运行状态，包括网络可用性和资源负载情况，为决策引擎提供输入。"""
        network_ready = pipeline_uploader.is_upload_channel_ready()
        snapshot = resource_monitor.snapshot()
        return RuntimeStatus(
            network_ready=network_ready,
            high_load=snapshot.high_load,
            cpu_percent=snapshot.cpu_percent,
            memory_percent=snapshot.memory_percent,
            network_reason=(None if network_ready else "upload_channel_unavailable"),
            load_reason=snapshot.reason,
        )

    pipeline = EdgePipeline(
        capture=capture,
        model_loader=model_loader,
        infer=infer,
        upload_coordinator=pipeline_uploader,
        spool=spool,
        decision_engine=decision_engine,
        runtime_status_provider=runtime_status_provider,
    )
    sync_worker = SyncWorker(
        upload_coordinator=sync_uploader,
        spool=spool,
        batch_size=cfg.runtime.sync_batch_size,
        interval_sec=cfg.runtime.sync_interval_sec,
    )

    if not args.loop:
        pipeline.run_once()
        sync_worker.drain_once()
        print("edge pipeline run_once done")
        return

    while True:
        pipeline.run_once()
        sync_worker.drain_once()
        time.sleep(max(args.interval_sec, 0.1))


if __name__ == "__main__":
    main()
