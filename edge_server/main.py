import argparse
import time
import tomllib
from pathlib import Path

from src.ignitor.factory import build_capture_module
from src.models.sys.func import load_edge_config
from src.models.sys.config import EdgeServerConfig
from src.orchestration.decision_engine import DecisionEngine
from src.orchestration.pipeline import EdgePipeline
from src.orchestration.runtime_signal import ResourceMonitor
from src.models.workflow.runtime import RuntimeStatus
from src.local_storage.sqlite_spool import SQLiteSpoolStorage
from src.local_storage.sqlite_auth_store import SQLiteEdgeAuthStateStore
from src.sync_worker.sync_worker import SyncWorker
from src.reasoner.infrencer import TwoStageInferenceModule
from src.reasoner.model_loader import LocalModelBundleLoader
from src.orchestration.auth_coordinator import EdgeAuthCoordinator
from src.transport.event_uploader import EdgeEventHttpUploadCoordinator
from src.transport.auth_transport import EdgeGatewayAuthHttpClient
from src.utils.runtime_logger import RuntimeEventLogger
from src.utils.secret_key_utils import SecretKeyUtils


def _build_auth_coordinator(
    cfg: EdgeServerConfig, event_logger: RuntimeEventLogger
) -> EdgeAuthCoordinator:
    key_manager = SecretKeyUtils.from_secret_dir(
        device_id=cfg.runtime.device_id,
        active_key_id=cfg.auth.active_key_id,
        secret_dir=cfg.auth.secret_key_dir,
    )
    auth_state_store = SQLiteEdgeAuthStateStore(
        db_path=cfg.auth.auth_state_db_path,
    )
    gateway_auth_client = EdgeGatewayAuthHttpClient(
        auth_base_url=cfg.upload_http.base_backend_url,
        auth_path=cfg.upload_http.auth_path,
        timeout_sec=cfg.upload_http.timeout_sec,
    )
    return EdgeAuthCoordinator(
        key_manager=key_manager,
        gateway_auth_client=gateway_auth_client,
        state_store=auth_state_store,
        event_logger=event_logger,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Edge server pipeline")
    parser.add_argument("--settings", default="settings.toml")
    loop_group = parser.add_mutually_exclusive_group()
    loop_group.add_argument(
        "--loop",
        dest="loop",
        action="store_true",
        default=True,
        help="Run pipeline in continuous loop mode (default).",
    )
    loop_group.add_argument(
        "--run-once",
        dest="loop",
        action="store_false",
        help="Run pipeline only once for local debugging.",
    )
    parser.add_argument("--interval-sec", type=float, default=1.0)
    return parser


def main() -> None:
    args = _build_parser().parse_args()
    settings_path = Path(args.settings).resolve()
    with settings_path.open("rb") as file:
        raw_settings = tomllib.load(file)
    cfg = load_edge_config(raw_settings, base_dir=settings_path.parent)
    event_logger = RuntimeEventLogger(cfg.runtime_log)
    event_logger.emit(
        stage="startup",
        event="config_loaded",
        details={
            "run_mode": cfg.runtime.run_mode,
            "device_id": cfg.runtime.device_id,
        },
    )

    capture = build_capture_module(cfg.capture, cfg.runtime.device_id)
    spool = SQLiteSpoolStorage(cfg.runtime.spool_db_path)
    is_development_mode = cfg.runtime.run_mode == "development"

    model_loader = LocalModelBundleLoader()
    model_loader.load(cfg.model_pack)
    infer = TwoStageInferenceModule()

    auth_coordinator = None
    if is_development_mode:
        event_logger.emit(
            stage="startup",
            event="development_mode_enabled",
            details={
                "auth_enabled": False,
                "outbound_enabled": False,
            },
        )
    else:
        if not cfg.auth.active_key_id and not cfg.runtime.device_id.strip():
            raise RuntimeError(
                "production mode requires at least one of auth.active_key_id or runtime.device_id"
            )
        auth_coordinator = _build_auth_coordinator(cfg, event_logger)
        auth_coordinator.ensure_startup_ready()
        event_logger.emit(
            stage="startup",
            event="production_startup_gate_passed",
            details={"auth_enabled": True},
        )

    pipeline_uploader = EdgeEventHttpUploadCoordinator(
        upload_url=cfg.upload_http.upload_url,
        healthcheck_url=cfg.upload_http.healthcheck_url,
        timeout_sec=cfg.upload_http.timeout_sec,
        auth_coordinator=auth_coordinator,
    )
    sync_uploader = EdgeEventHttpUploadCoordinator(
        upload_url=cfg.upload_http.upload_url,
        healthcheck_url=cfg.upload_http.healthcheck_url,
        timeout_sec=cfg.upload_http.timeout_sec,
        auth_coordinator=auth_coordinator,
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
        snapshot = resource_monitor.snapshot()
        if is_development_mode:
            return RuntimeStatus(
                network_ready=False,
                high_load=snapshot.high_load,
                cpu_percent=snapshot.cpu_percent,
                memory_percent=snapshot.memory_percent,
                network_reason="development_mode_no_upload",
                load_reason=snapshot.reason,
            )

        network_ready = pipeline_uploader.is_upload_endpoint_ready()
        return RuntimeStatus(
            network_ready=network_ready,
            high_load=snapshot.high_load,
            cpu_percent=snapshot.cpu_percent,
            memory_percent=snapshot.memory_percent,
            network_reason=(None if network_ready else "upload_endpoint_unavailable"),
            load_reason=snapshot.reason,
        )

    def ensure_runtime_auth_gate() -> None:
        if auth_coordinator is None:
            return
        # 生产模式：每轮业务处理前都确保长期凭证仍可用；缺失时尝试 bootstrap。
        auth_coordinator.ensure_startup_ready()

    pipeline = EdgePipeline(
        capture=capture,
        model_loader=model_loader,
        infer=infer,
        upload_coordinator=pipeline_uploader,
        spool=spool,
        decision_engine=decision_engine,
        runtime_status_provider=runtime_status_provider,
        event_logger=event_logger,
    )
    sync_worker = SyncWorker(
        upload_coordinator=sync_uploader,
        spool=spool,
        batch_size=cfg.runtime.sync_batch_size,
        interval_sec=cfg.runtime.sync_interval_sec,
        event_logger=event_logger,
    )

    if not args.loop:
        ensure_runtime_auth_gate()
        pipeline.run_once()
        if not is_development_mode:
            sync_worker.drain_once()
        print("edge pipeline run_once done")
        return

    while True:
        ensure_runtime_auth_gate()
        pipeline.run_once()
        if not is_development_mode:
            sync_worker.drain_once()
        time.sleep(max(args.interval_sec, 0.1))


if __name__ == "__main__":
    main()
