from __future__ import annotations

import logging

from src.models.sys.config import EtcdConfig, ProjectConfig, RuntimeConfig
from src.models.sys.config_loader import load_project_config_from_toml


DEFAULT_SETTINGS_PATH = "settings.toml"
DEFAULT_ETCD_ENDPOINT = "127.0.0.1:2379"


def run() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    _run_server()


def _run_server() -> None:
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
    logger.info(
        "stage=dependencies_initialized service=%s",
        runtime_cfg.service_name,
    )
    logger.info(
        "stage=server_listen service=%s transport=grpc addr=%s",
        runtime_cfg.service_name,
        f"{runtime_cfg.grpc_listen_host}:{runtime_cfg.grpc_listen_port}",
    )


def resolve_project_config(
    settings_path: str, default_etcd_endpoint: str
) -> ProjectConfig:
    config = load_project_config_from_toml(settings_path)
    if config.etcd is None:
        config.etcd = EtcdConfig(HOSTS=[default_etcd_endpoint], NAMESPACE="/bms")
    elif not config.etcd.HOSTS:
        config.etcd.HOSTS = [default_etcd_endpoint]
    return config
