from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
from uuid import UUID, uuid4
import grpc

from src.iface.common.local_credential_manager import (
    ILocalCredentialManager,
)
from src.iface.communication.traffic_station import ITrafficStation
from src.models.common.instance import ServiceInstance
from src.models.sys.config import (
    EtcdConfig,
    ProjectConfig,
    RuntimeConfig,
    load_project_config_from_toml,
)
from src.repo.etcd_client import EtcdAsyncClient
from src.repo.redis_store import RedisManager
from src.services.common.registry_svc import RegistryService
from src.services.common.local_credential_svc import LocalCredentialService
from src.services.common.secret_key_svc import SecretKeyService
from src.services.communication.routing_payload_pipeline_svc import (
    RoutingPayloadPipelineService,
)
from src.services.communication.traffic_station_svc import TrafficStationService
from src.services.orchestration.bootstrap_startup_orchestrator_svc import (
    BootstrapStartupOrchestratorService,
)
from src.services.orchestration.worker_orchestrator_svc import WorkerOrchestratorService


DEFAULT_SETTINGS_PATH = "settings.toml"
DEFAULT_ETCD_ENDPOINT = "127.0.0.1:2379"
DEFAULT_REGISTRY_TTL_SEC = 30
DEFAULT_AUTH_AUTHORITY_SERVICE = "certification_server"


def run() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        asyncio.run(run_data_worker())
    except KeyboardInterrupt:
        logging.getLogger("data_worker.startup").info("data_worker interrupted")


async def run_data_worker() -> None:
    logger = logging.getLogger("data_worker.startup")

    config = resolve_project_config(DEFAULT_SETTINGS_PATH, DEFAULT_ETCD_ENDPOINT)
    runtime_cfg = (
        config.runtime.normalized("data_worker")
        if config.runtime is not None
        else RuntimeConfig().normalized("data_worker")
    )
    logger.info(
        "stage=config_loaded service=%s run_mode=%s",
        runtime_cfg.service_name,
        runtime_cfg.run_mode,
    )

    etcd_client: EtcdAsyncClient | None = None
    redis_manager: RedisManager | None = None
    registry_service: RegistryService | None = None
    traffic_station: ITrafficStation | None = None
    local_credential_manager: ILocalCredentialManager | None = None
    registered_instance: ServiceInstance | None = None
    worker_server: grpc.aio.Server | None = None

    try:
        etcd_client = EtcdAsyncClient(config)
        await etcd_client.connect()
        registry_service = RegistryService(etcd_client=etcd_client)
        routing_pipeline = RoutingPayloadPipelineService(
            registry_service=registry_service,
            auth_authority_service=DEFAULT_AUTH_AUTHORITY_SERVICE,
            run_mode=runtime_cfg.run_mode,
        )
        traffic_station = TrafficStationService(routing_pipeline=routing_pipeline)
        _ = WorkerOrchestratorService(traffic_station=traffic_station)

        if config.redis is not None:
            redis_manager = RedisManager(config)
            await redis_manager.connect()
            local_credential_manager = LocalCredentialService(
                redis_client=redis_manager.get_client()
            )

        _, startup_params = SecretKeyService.from_project_config(
            config=config,
            default_entity_id="data_worker",
        )
        logger.info(
            "stage=dependencies_initialized service=%s", runtime_cfg.service_name
        )

        if runtime_cfg.run_mode == "no_auth":
            logger.info(
                "stage=bootstrap_skipped_or_ready service=%s mode=no_auth",
                runtime_cfg.service_name,
            )
        else:
            await ensure_worker_bootstrap_ready(
                runtime_cfg=runtime_cfg,
                startup_params=startup_params,
                traffic_station=traffic_station,
                local_credential_manager=local_credential_manager,
            )

        instance = build_worker_instance(
            runtime_cfg=runtime_cfg,
            active_key_id=startup_params.active_key_id,
        )
        registered_instance = instance

        logger.info(
            "stage=registry_register_attempt service=%s instance=%s",
            instance.name,
            str(instance.id),
        )
        await registry_service.register(instance, ttl_sec=DEFAULT_REGISTRY_TTL_SEC)
        logger.info(
            "stage=registry_register_success service=%s instance=%s endpoint=%s",
            instance.name,
            str(instance.id),
            instance.endpoint,
        )

        logger.info(
            "stage=server_start_attempt service=%s transport=grpc addr=%s",
            runtime_cfg.service_name,
            build_worker_listen_addr(runtime_cfg),
        )

        worker_server = grpc.aio.server()
        bound_port = worker_server.add_insecure_port(
            build_worker_listen_addr(runtime_cfg)
        )
        if bound_port <= 0:
            raise RuntimeError("data_worker grpc listener bind failed")
        await worker_server.start()

        stop_event = asyncio.Event()
        install_signal_handlers(stop_event)
        logger.info(
            "stage=server_start_success service=%s transport=grpc addr=%s",
            runtime_cfg.service_name,
            build_worker_listen_addr(runtime_cfg),
        )
        await stop_event.wait()
    finally:
        if worker_server is not None:
            with contextlib.suppress(Exception):
                await worker_server.stop(grace=5)
        if registry_service is not None and registered_instance is not None:
            with contextlib.suppress(Exception):
                await registry_service.unregister(registered_instance)
        if redis_manager is not None:
            with contextlib.suppress(Exception):
                await redis_manager.disconnect()
        if etcd_client is not None:
            with contextlib.suppress(Exception):
                await etcd_client.close()


def resolve_project_config(
    settings_path: str, default_etcd_endpoint: str
) -> ProjectConfig:
    config = load_project_config_from_toml(settings_path)
    if config.etcd is None:
        config.etcd = EtcdConfig(HOSTS=[default_etcd_endpoint], NAMESPACE="/bms")
    elif not config.etcd.HOSTS:
        config.etcd.HOSTS = [default_etcd_endpoint]
    return config


def build_worker_instance(
    runtime_cfg: RuntimeConfig, active_key_id: str
) -> ServiceInstance:
    instance_id = parse_or_create_uuid(runtime_cfg.instance_id)
    service_id = runtime_cfg.instance_id.strip() or str(instance_id)
    return ServiceInstance(
        id=instance_id,
        service_id=service_id,
        name=runtime_cfg.service_name,
        endpoint=f"{runtime_cfg.grpc_listen_host}:{runtime_cfg.grpc_listen_port}",
        heartbeat=0,
        weight=1,
        tags=["data_worker", "grpc", "startup_phase"],
        active_comm_key_id=active_key_id.strip(),
        metadata={
            "run_mode": runtime_cfg.run_mode,
            "startup_phase": "bootstrap_to_registry",
        },
    )


def parse_or_create_uuid(raw: str) -> UUID:
    candidate = (raw or "").strip()
    if candidate:
        try:
            return UUID(candidate)
        except ValueError:
            pass
    return uuid4()


async def ensure_worker_bootstrap_ready(
    runtime_cfg: RuntimeConfig,
    startup_params,
    traffic_station: ITrafficStation,
    local_credential_manager: ILocalCredentialManager | None,
) -> None:
    logger = logging.getLogger("data_worker.startup")
    if local_credential_manager is None:
        raise RuntimeError("local credential manager dependencies are required")
    startup_orchestrator = BootstrapStartupOrchestratorService(
        traffic_station=traffic_station,
        local_credential_manager=local_credential_manager,
        auth_authority_service=DEFAULT_AUTH_AUTHORITY_SERVICE,
    )
    result = await startup_orchestrator.ensure_ready(
        runtime_cfg=runtime_cfg,
        startup_params=startup_params,
    )

    logger.info(
        "stage=bootstrap_skipped_or_ready service=%s mode=%s auth_authority=%s authority_endpoint=%s stage=%s credential_key=%s",
        runtime_cfg.service_name,
        runtime_cfg.run_mode,
        DEFAULT_AUTH_AUTHORITY_SERVICE,
        result.authority_endpoint,
        result.stage,
        result.credential_key,
    )


def install_signal_handlers(stop_event: asyncio.Event) -> None:
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, stop_event.set)


def build_worker_listen_addr(runtime_cfg: RuntimeConfig) -> str:
    host = (runtime_cfg.grpc_listen_host or "").strip() or "127.0.0.1"
    return f"{host}:{runtime_cfg.grpc_listen_port}"
