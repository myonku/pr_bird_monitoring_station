from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
from uuid import NAMESPACE_DNS, UUID, uuid4, uuid5
import grpc

from src.gen.business.v1 import business_forward_pb2_grpc
from src.iface.common.local_credential_manager import (
    ILocalCredentialManager,
)
from src.iface.common.local_credential_manager import ModuleCredentialSnapshot
from src.iface.auth.bootstrap_coordinator import IBootstrapCoordinator
from src.iface.communication.traffic_station import ITrafficStation
from src.models.common.instance import ServiceInstance
from src.models.business.data import BUSINESS_DOCUMENT_MODELS
from src.models.sys.config import (
    EtcdConfig,
    ProjectConfig,
    RuntimeConfig,
    SecretKeyStartupParams,
)
from src.models.sys.config_loader import load_project_config_from_toml
from src.repo.etcd_client import EtcdAsyncClient
from src.repo.mongo_client import MongoDBClient
from src.repo.mysql_client import MySQLClient
from src.repo.redis_store import RedisManager
from src.services.business.data_server_svc import DataServerService
from src.services.business.envelope_svc import EnvelopeManager
from src.services.business.monitoring_record_svc import MonitoringRecordManager
from src.services.business.species_profile_svc import SpeciesProfileManager
from src.services.business.user_entity_svc import UserEntityManager
from src.services.business.user_profile_svc import UserProfileManager
from src.services.business.device_entity_svc import DeviceEntityManager
from src.services.communication.rpc_service.business_forward_servicer import (
    BusinessForwardServicer,
)
from src.services.common.registry_svc import RegistryService
from src.services.common.local_credential_svc import LocalCredentialService
from src.iface.common.key_manager import ISecretKeyManager
from src.services.communication.routing_payload_pipeline_svc import (
    RoutingPayloadPipelineService,
)
from src.services.communication.traffic_station_svc import TrafficStationService
from src.services.orchestration.credential_discovery_supervisor_svc import (
    CredentialDiscoverySupervisorService,
)
from src.services.auth.bootstrap_coordinator_svc import BootstrapCoordinatorService
from src.services.orchestration.startup_security_svc import (
    resolve_startup_security_materials,
)
from src.services.orchestration.server_orchestrator_svc import (
    ServerOrchestratorService,
)
from src.services.authcontrol.inbound_auth_control_svc import (
    InboundAuthControlService,
)


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
        asyncio.run(run_data_server())
    except KeyboardInterrupt:
        logging.getLogger("startup").info("data_server interrupted")


async def run_data_server() -> None:
    logger = logging.getLogger("startup")

    config = resolve_project_config(DEFAULT_SETTINGS_PATH, DEFAULT_ETCD_ENDPOINT)
    runtime_cfg = (
        config.runtime.normalized("data_server")
        if config.runtime is not None
        else RuntimeConfig().normalized("data_server")
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
    secret_key_service: ISecretKeyManager | None = None
    startup_params: SecretKeyStartupParams | None = None
    bootstrap_coordinator: IBootstrapCoordinator | None = None
    mongo_client: MongoDBClient | None = None
    mysql_client: MySQLClient | None = None
    business_forward_servicer: BusinessForwardServicer | None = None
    registered_instance: ServiceInstance | None = None
    server_server: grpc.aio.Server | None = None
    credential_supervisor: CredentialDiscoverySupervisorService | None = None
    credential_supervisor_task: asyncio.Task[None] | None = None
    stop_event = asyncio.Event()

    try:
        etcd_client = EtcdAsyncClient(config)
        await etcd_client.connect()
        registry_service = RegistryService(etcd_client=etcd_client)
        routing_pipeline = RoutingPayloadPipelineService(
            registry_service=registry_service,
            auth_authority_service=DEFAULT_AUTH_AUTHORITY_SERVICE,
            run_mode=runtime_cfg.run_mode,
        )
        auth_control_svc = InboundAuthControlService(cfg=config.auth_control)
        traffic_station = TrafficStationService(
            routing_pipeline=routing_pipeline,
            auth_control=auth_control_svc,
        )
        _ = ServerOrchestratorService(traffic_station=traffic_station)

        startup_params, secret_key_service = resolve_startup_security_materials(
            config=config,
            runtime_cfg=runtime_cfg,
            default_entity_id="data_server",
        )

        if config.redis is not None:
            redis_manager = RedisManager(config)
            await redis_manager.connect()
            local_credential_manager = LocalCredentialService(
                redis_client=redis_manager.get_client()
            )

        logger.info(
            "stage=dependencies_initialized service=%s", runtime_cfg.service_name
        )

        if config.mongo is None or config.mysql is None:
            logger.warning(
                "stage=business_forward_skipped service=%s reason=missing_storage_config",
                runtime_cfg.service_name,
            )
        else:
            mongo_client = MongoDBClient(config)
            await mongo_client.connect(document_models=BUSINESS_DOCUMENT_MODELS)

            mysql_client = MySQLClient(config)
            await mysql_client.connect()

            business_forward_servicer = BusinessForwardServicer(
                traffic_station=traffic_station,
                data_server_service=DataServerService(
                    user_profile_manager=UserProfileManager(),
                    user_entity_manager=UserEntityManager(mysql_client=mysql_client),
                    device_entity_manager=DeviceEntityManager(mysql_client=mysql_client),
                    species_profile_manager=SpeciesProfileManager(
                        mysql_client=mysql_client
                    ),
                    record_manager=MonitoringRecordManager(),
                    envelope_manager=EnvelopeManager(),
                ),
                expected_service_name=runtime_cfg.service_name,
            )
            logger.info(
                "stage=business_forward_wired service=%s storage=mongo_mysql",
                runtime_cfg.service_name,
            )

        if runtime_cfg.run_mode == "no_auth":
            logger.info(
                "stage=bootstrap_skipped_or_ready service=%s mode=no_auth",
                runtime_cfg.service_name,
            )
            resolved_active_key_id = startup_params.active_key_id if startup_params else ""
        else:
            if local_credential_manager is None:
                raise RuntimeError("local credential manager dependencies are required")
            if secret_key_service is None or startup_params is None:
                raise RuntimeError("secret key dependencies are required")
            bootstrap_coordinator = BootstrapCoordinatorService(
                runtime_cfg=runtime_cfg,
                startup_params=startup_params,
                traffic_station=traffic_station,
                local_credential_manager=local_credential_manager,
                secret_key_service=secret_key_service,
                auth_authority_service=DEFAULT_AUTH_AUTHORITY_SERVICE,
            )
            bootstrap_snapshot = await ensure_server_bootstrap_ready(
                runtime_cfg=runtime_cfg,
                bootstrap_coordinator=bootstrap_coordinator,
            )
            resolved_active_key_id = (
                (bootstrap_snapshot.active_comm_key_id if bootstrap_snapshot is not None else "")
                or startup_params.active_key_id
                or (
                    startup_params.instance_id
                    or runtime_cfg.instance_id
                    or runtime_cfg.service_name
                )
            )

        instance = build_server_instance(
            runtime_cfg=runtime_cfg,
            active_key_id=resolved_active_key_id,
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

        if runtime_cfg.run_mode != "no_auth":
            assert local_credential_manager is not None
            assert bootstrap_coordinator is not None
            credential_supervisor = CredentialDiscoverySupervisorService(
                runtime_cfg=runtime_cfg,
                local_credential_manager=local_credential_manager,
                registry_service=registry_service,
                service_instance_factory=lambda active_key_id: build_server_instance(
                    runtime_cfg=runtime_cfg,
                    active_key_id=active_key_id,
                ),
                bootstrap_coordinator=bootstrap_coordinator,
                registry_ttl_sec=DEFAULT_REGISTRY_TTL_SEC,
            )
            credential_supervisor_task = asyncio.create_task(
                credential_supervisor.run(
                    stop_event=stop_event,
                    registered_instance=registered_instance,
                )
            )

        logger.info(
            "stage=server_start_attempt service=%s transport=grpc addr=%s",
            runtime_cfg.service_name,
            build_server_listen_addr(runtime_cfg),
        )

        server_server = grpc.aio.server()
        bound_port = server_server.add_insecure_port(
            build_server_listen_addr(runtime_cfg)
        )
        if bound_port <= 0:
            raise RuntimeError("data_server grpc listener bind failed")

        if business_forward_servicer is not None:
            business_forward_pb2_grpc.add_BusinessForwardServiceServicer_to_server(
                business_forward_servicer,
                server_server,
            )
        await server_server.start()

        install_signal_handlers(stop_event)
        logger.info(
            "stage=server_start_success service=%s transport=grpc addr=%s",
            runtime_cfg.service_name,
            build_server_listen_addr(runtime_cfg),
        )
        await stop_event.wait()
    finally:
        if credential_supervisor_task is not None:
            credential_supervisor_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await credential_supervisor_task
        if bootstrap_coordinator is not None and runtime_cfg.run_mode != "no_auth":
            with contextlib.suppress(Exception):
                await bootstrap_coordinator.revoke_module_credential("shutdown")
        if server_server is not None:
            with contextlib.suppress(Exception):
                await server_server.stop(grace=5)
        if registry_service is not None and registered_instance is not None:
            with contextlib.suppress(Exception):
                await registry_service.unregister(registered_instance)
        if mysql_client is not None:
            with contextlib.suppress(Exception):
                await mysql_client.disconnect()
        if mongo_client is not None:
            with contextlib.suppress(Exception):
                await mongo_client.disconnect()
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


def build_server_instance(
    runtime_cfg: RuntimeConfig, active_key_id: str
) -> ServiceInstance:
    instance_id = parse_or_create_uuid(runtime_cfg.instance_id)
    service_id = runtime_cfg.instance_id.strip() or str(instance_id)
    resolved_active_key_id = active_key_id.strip() or service_id
    return ServiceInstance(
        id=instance_id,
        service_id=service_id,
        name=runtime_cfg.service_name,
        endpoint=f"{runtime_cfg.grpc_listen_host}:{runtime_cfg.grpc_listen_port}",
        heartbeat=0,
        weight=1,
        tags=["data_server", "grpc", "startup_phase"],
        active_comm_key_id=resolved_active_key_id,
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
            return uuid5(NAMESPACE_DNS, candidate)
    return uuid4()


def build_server_listen_addr(runtime_cfg: RuntimeConfig) -> str:
    return f"{runtime_cfg.grpc_listen_host}:{runtime_cfg.grpc_listen_port}"


async def ensure_server_bootstrap_ready(
    runtime_cfg: RuntimeConfig,
    bootstrap_coordinator: IBootstrapCoordinator,
) -> ModuleCredentialSnapshot:
    logger = logging.getLogger("startup")
    snapshot = await bootstrap_coordinator.ensure_module_ready()
    if snapshot is None:
        raise RuntimeError(
            f"service={runtime_cfg.service_name} "
            "bootstrap credential snapshot is None"
        )
    logger.info(
        "stage=bootstrap_ready service=%s principal_id=%s stage=%s",
        runtime_cfg.service_name,
        snapshot.principal_id,
        snapshot.stage,
    )
    return snapshot


def install_signal_handlers(stop_event: asyncio.Event) -> None:
    loop = asyncio.get_event_loop()

    def _signal_handler() -> None:
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _signal_handler)
        except (NotImplementedError, ValueError):
            pass
