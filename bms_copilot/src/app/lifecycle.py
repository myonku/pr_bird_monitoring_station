from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
from typing import Any
from uuid import NAMESPACE_DNS, UUID, uuid4, uuid5

import grpc

from src.gen.business.v1 import business_forward_pb2_grpc
from src.models.agent.audit import AgentAuditEvent
from src.models.agent.tool_record import ToolCallRecord, ToolResultRecord
from src.models.agent.session import RunRecord
from src.models.agent.usage import UsageRecord
from src.models.business.event import BUSINESS_DOCUMENT_MODELS
from src.models.sys.config import EtcdConfig, ProjectConfig, RuntimeConfig
from src.models.sys.config_loader import load_project_config_from_toml
from src.repo.etcd_client import EtcdAsyncClient
from src.repo.mongo_client import MongoDBClient
from src.repo.mysql_client import MySQLClient
from src.repo.redis_store import RedisManager
from src.services.common.registry_svc import RegistryService
from src.services.communication.routing_payload_pipeline_svc import (
    RoutingPayloadPipelineService,
)
from src.services.communication.traffic_station_svc import TrafficStationService
from src.services.authcontrol.inbound_auth_control_svc import (
    InboundAuthControlService,
)

AGENT_DOCUMENT_MODELS = [
    AgentAuditEvent,
    ToolCallRecord,
    ToolResultRecord,
    RunRecord,
    UsageRecord,
]

DEFAULT_SETTINGS_PATH = "settings.toml"
DEFAULT_ETCD_ENDPOINT = "127.0.0.1:2379"
DEFAULT_REGISTRY_TTL_SEC = 30


def run() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        asyncio.run(run_bms_copilot())
    except KeyboardInterrupt:
        logging.getLogger("startup").info("bms_copilot interrupted")


async def run_bms_copilot() -> None:
    logger = logging.getLogger("startup")

    config = _resolve_config(DEFAULT_SETTINGS_PATH)
    runtime_cfg = (
        config.runtime.normalized("bms_copilot")
        if config.runtime is not None
        else RuntimeConfig().normalized("bms_copilot")
    )
    logger.info(
        "stage=startup service=%s run_mode=%s",
        runtime_cfg.service_name,
        runtime_cfg.run_mode,
    )

    etcd_client: EtcdAsyncClient | None = None
    registry_service: RegistryService | None = None
    stop_event = asyncio.Event()
    server: grpc.aio.Server | None = None
    bootstrapped = False

    try:
        etcd_client = EtcdAsyncClient(config)
        await etcd_client.connect()
        registry_service = RegistryService(etcd_client=etcd_client)
        routing_pipeline = RoutingPayloadPipelineService(
            registry_service=registry_service,
            auth_authority_service="certification_server",
            run_mode=runtime_cfg.run_mode,
        )
        auth_control_svc = InboundAuthControlService(cfg=config.auth_control)
        traffic_station = TrafficStationService(
            routing_pipeline=routing_pipeline,
            auth_control=auth_control_svc,
        )
        logger.info("stage=infra_ready service=%s", runtime_cfg.service_name)

        redis_client = None
        if config.redis is not None:
            rm = RedisManager(config)
            await rm.connect()
            redis_client = rm.get_client()
            logger.info("stage=redis_connected service=%s", runtime_cfg.service_name)

        mongo_client = None
        if config.mongo is not None:
            mc = MongoDBClient(config)
            await mc.connect(
                document_models=[
                    *BUSINESS_DOCUMENT_MODELS,
                    *AGENT_DOCUMENT_MODELS,
                ]
            )
            mongo_client = mc
            logger.info("stage=mongo_connected service=%s", runtime_cfg.service_name)

        mysql_client = None
        if config.mysql is not None:
            mc = MySQLClient(config)
            await mc.connect()
            mysql_client = mc
            logger.info("stage=mysql_connected service=%s", runtime_cfg.service_name)

        resource_stores: dict[str, Any] | None = None
        rc: Any = redis_client
        if redis_client is not None:
            from src.agent_core.resource.session_store import RedisSessionStore
            from src.agent_core.resource.turn_store import RedisTurnStore
            from src.agent_core.resource.working_memory import (
                RedisWorkingStateCache,
            )

            resource_stores = {
                "session_store": RedisSessionStore(rc),
                "turn_store": RedisTurnStore(rc),
                "state_cache": RedisWorkingStateCache(rc),
            }
            logger.info("stage=resources_ready service=%s", runtime_cfg.service_name)

        agent_cfg = config.agent
        chat_provider = None
        if agent_cfg is not None:
            from src.agent_core.provider.chat_provider.deepseek import (
                DeepSeekChatProvider,
            )

            chat_provider = DeepSeekChatProvider(config=agent_cfg)

        inference_tool = None
        if config.inference is not None:
            from src.agent_core.tools.inference import ImageInferenceTool

            inference_tool = ImageInferenceTool(
                config=config,
                base_dir=".",
                enable_species_resolver=False,
            )

        query_tool = None
        if mysql_client is not None or mongo_client is not None:
            from src.agent_core.tools.query import QueryRecordsTool
            from src.modules.query.engine import QueryEngine

            engine = QueryEngine(
                mongo_client=mongo_client,
                mysql_client=mysql_client,
            )
            query_tool = QueryRecordsTool(engine=engine)

        registry = None
        if inference_tool is not None or query_tool is not None:
            from src.iface.agent.tools import ITool, IToolRegistry

            class _ToolRegistry(IToolRegistry):
                def __init__(self) -> None:
                    self._tools: dict[str, ITool] = {}

                def register(self, t: ITool) -> None:
                    self._tools[t.name] = t

                def get(self, tool_name: str) -> ITool:
                    t = self._tools.get(tool_name)
                    if t is None:
                        raise KeyError(f"tool not found: {tool_name}")
                    return t

                def has(self, tool_name: str) -> bool:
                    return tool_name in self._tools

                def list_tools(self) -> dict[str, ITool]:
                    return dict(self._tools)

            registry = _ToolRegistry()
            if inference_tool is not None:
                registry.register(inference_tool)
            if query_tool is not None:
                registry.register(query_tool)

        orchestrator = None
        if chat_provider is not None and registry is not None:
            from src.agent_core.orchestrator.agent import AgentOrchestrator
            from src.agent_core.orchestrator.router import PromptIntentClassifier
            from src.agent_core.orchestrator.planner import PromptToolPlanner
            from src.agent_core.orchestrator.synthesizer import (
                PromptResponseSynthesizer,
            )

            model_name = agent_cfg.model if agent_cfg else ""
            orchestrator = AgentOrchestrator(
                tool_registry=registry,
                classifier=PromptIntentClassifier(
                    provider=chat_provider, model=model_name
                ),
                planner=PromptToolPlanner(provider=chat_provider, model=model_name),
                synthesizer=PromptResponseSynthesizer(
                    provider=chat_provider, model=model_name
                ),
            )

        conversation_memory = None
        if redis_client is not None and resource_stores is not None:
            from src.agent_core.memory.conversation_store import (
                ConversationMemory,
            )

            conversation_memory = ConversationMemory(
                redis=rc,
                session_store=resource_stores["session_store"],
                turn_store=resource_stores["turn_store"],
                working_state_cache=resource_stores.get("state_cache"),
            )
            if orchestrator is not None:
                orchestrator.memory = conversation_memory

        chat_service = None
        if orchestrator is not None and resource_stores is not None:
            from src.services.business.chat_service import ChatService

            chat_service = ChatService(
                orchestrator=orchestrator,
                session_store=resource_stores["session_store"],
                turn_store=resource_stores["turn_store"],
                provider_name=agent_cfg.provider if agent_cfg else "",
                model_name=agent_cfg.model if agent_cfg else "",
            )

        logger.info(
            "stage=agent_core_ready service=%s",
            runtime_cfg.service_name,
        )

        business_servicer = None
        if chat_service is not None:
            from src.services.communication.rpc_service.business_forward_servicer import (
                BusinessForwardServicer,
            )

            business_servicer = BusinessForwardServicer(
                traffic_station=traffic_station,
                chat_service=chat_service,
                expected_service_name=runtime_cfg.service_name,
            )
            logger.info("stage=servicer_ready service=%s", runtime_cfg.service_name)

        if runtime_cfg.run_mode == "no_auth":
            logger.info(
                "stage=bootstrap_skipped service=%s mode=no_auth",
                runtime_cfg.service_name,
            )
            bootstrapped = True
        else:
            logger.info("stage=bootstrap_start service=%s", runtime_cfg.service_name)
            bootstrapped = True  # TODO: add full bootstrap flow
            logger.info("stage=bootstrap_ready service=%s", runtime_cfg.service_name)

        instance = _build_instance(runtime_cfg)
        await registry_service.register(instance, ttl_sec=DEFAULT_REGISTRY_TTL_SEC)
        logger.info(
            "stage=registry_success service=%s endpoint=%s",
            instance.name,
            instance.endpoint,
        )

        server = grpc.aio.server()
        addr = f"{runtime_cfg.grpc_listen_host}:{runtime_cfg.grpc_listen_port}"
        bound = server.add_insecure_port(addr)
        if bound <= 0:
            raise RuntimeError("gRPC listener bind failed")

        if business_servicer is not None:
            business_forward_pb2_grpc.add_BusinessForwardServiceServicer_to_server(
                business_servicer, server
            )

        await server.start()
        logger.info(
            "stage=server_started service=%s addr=%s run_mode=%s",
            runtime_cfg.service_name,
            addr,
            runtime_cfg.run_mode,
        )

        _install_signal_handlers(stop_event)
        await stop_event.wait()

    finally:
        if server is not None:
            with contextlib.suppress(Exception):
                await server.stop(grace=5)
        if registry_service is not None and bootstrapped:
            with contextlib.suppress(Exception):
                await registry_service.unregister(_build_instance(runtime_cfg))
        if etcd_client is not None:
            with contextlib.suppress(Exception):
                await etcd_client.close()
        logger.info("stage=shutdown service=%s", runtime_cfg.service_name)


def _build_instance(
    runtime_cfg: RuntimeConfig,
) -> Any:
    from src.models.common.instance import ServiceInstance

    return ServiceInstance(
        id=_parse_or_create_uuid(runtime_cfg.instance_id),
        service_id=runtime_cfg.instance_id.strip() or runtime_cfg.service_name,
        name=runtime_cfg.service_name,
        endpoint=f"{runtime_cfg.grpc_listen_host}:{runtime_cfg.grpc_listen_port}",
        heartbeat=0,
        weight=1,
        tags=["bms_copilot", "grpc"],
        active_comm_key_id=runtime_cfg.instance_id,
        metadata={"run_mode": runtime_cfg.run_mode},
    )


def _resolve_config(settings_path: str) -> ProjectConfig:
    config = load_project_config_from_toml(settings_path)
    if config.etcd is None:
        config.etcd = EtcdConfig(HOSTS=[DEFAULT_ETCD_ENDPOINT], NAMESPACE="/bms")
    elif not config.etcd.HOSTS:
        config.etcd.HOSTS = [DEFAULT_ETCD_ENDPOINT]
    return config


def _parse_or_create_uuid(raw: str) -> UUID:
    candidate = (raw or "").strip()
    if candidate:
        try:
            return UUID(candidate)
        except ValueError:
            return uuid5(NAMESPACE_DNS, candidate)
    return uuid4()


def _install_signal_handlers(stop_event: asyncio.Event) -> None:
    loop = asyncio.get_event_loop()

    def _handler() -> None:
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handler)
        except (NotImplementedError, ValueError):
            pass
