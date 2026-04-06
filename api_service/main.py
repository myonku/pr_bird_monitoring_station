from __future__ import annotations

import argparse
import asyncio
import contextlib
import os
import tomllib
from pathlib import Path
from typing import Any, Literal, cast

from src.adapters.grpc.server_adapter import (
    GrpcServerAdapter,
    InMemoryGrpcRequest,
    InMemoryGrpcResponse,
)
from src.app.app import ServiceApp
from src.app.lifecycle import HookLifecycle
from src.app.internal_assertion_assembly import wire_internal_assertion_verification
from src.models.auth.internal_header_keys import HEADER_INTERNAL_ASSERTION
from src.models.commsec.commsec import ServiceKeyOwner
from src.models.sys.config import (
    AuthConfig,
    InternalAssertionConfig,
    ProjectConfig,
    RedisConfig,
    RuntimeConfig,
    SecretKeyStartupParams,
)
from src.repo.redis_store import RedisManager
from src.services.commsec.secret_key_svc import SecretKeyService
from src.services.auth.runtime_metrics import AuthRuntimeMetrics


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="api_service runtime")
    parser.add_argument("--settings", default="settings.toml")
    return parser


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw.strip())
    except ValueError:
        return default


def _to_bool(raw: Any, default: bool) -> bool:
    if isinstance(raw, bool):
        return raw
    if raw is None:
        return default
    if isinstance(raw, (int, float)):
        return bool(raw)
    if isinstance(raw, str):
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    return default


def _to_int(raw: Any, default: int) -> int:
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def _to_int_or_none(raw: Any) -> int | None:
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _to_str(raw: Any, default: str = "") -> str:
    if raw is None:
        return default
    value = str(raw).strip()
    return value if value else default


def _as_dict(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    return {}


def _as_list_of_str(raw: Any) -> list[str]:
    if not isinstance(raw, list):
        return []
    values: list[str] = []
    for item in raw:
        value = str(item).strip()
        if value:
            values.append(value)
    return values


def _read_settings_file(settings_path: Path) -> dict[str, Any]:
    if not settings_path.exists():
        return {}
    with settings_path.open("rb") as file:
        loaded = tomllib.load(file)
    return loaded if isinstance(loaded, dict) else {}


def _build_redis_config(section: dict[str, Any]) -> RedisConfig | None:
    if not section:
        return None

    mode_raw = _to_str(section.get("mode"), "single").lower()
    if mode_raw not in {"single", "cluster", "sentinel"}:
        mode_raw = "single"
    mode = cast(Literal["single", "cluster", "sentinel"], mode_raw)

    hosts = _as_list_of_str(section.get("hosts"))
    host = _to_str(section.get("host"), "")
    if host and not hosts:
        hosts = [host]

    password_raw = section.get("password")
    password = str(password_raw).strip() if password_raw is not None else None
    if password == "":
        password = None

    return RedisConfig(
        MODE=mode,
        DIALECT=_to_str(section.get("dialect"), "redis"),
        HOST=host or None,
        PORT=_to_int_or_none(section.get("port")),
        PASSWORD=password,
        DATABASE=_to_int(section.get("database"), 0),
        HOSTS=hosts or None,
    )


def _build_runtime_config(
    section: dict[str, Any],
    legacy_secret_key_section: dict[str, Any],
) -> RuntimeConfig:
    entity_type = _to_str(section.get("entity_type"), "")
    entity_id = _to_str(section.get("entity_id"), "")
    entity_name = _to_str(section.get("entity_name"), "")
    instance_id = _to_str(section.get("instance_id"), "")
    instance_name = _to_str(section.get("instance_name"), "")

    if legacy_secret_key_section:
        entity_type = entity_type or _to_str(
            legacy_secret_key_section.get("entity_type"),
            "service",
        )
        entity_id = entity_id or _to_str(
            legacy_secret_key_section.get("entity_id"),
            _to_str(legacy_secret_key_section.get("service_id"), ""),
        )
        entity_name = entity_name or _to_str(
            legacy_secret_key_section.get("entity_name"),
            _to_str(legacy_secret_key_section.get("service_name"), ""),
        )
        instance_id = instance_id or _to_str(
            legacy_secret_key_section.get("instance_id"),
            "",
        )
        instance_name = instance_name or _to_str(
            legacy_secret_key_section.get("instance_name"),
            "",
        )

    return RuntimeConfig(
        entity_type=entity_type or "service",
        entity_id=entity_id,
        entity_name=entity_name,
        instance_id=instance_id,
        instance_name=instance_name,
    )


def _build_auth_config(
    section: dict[str, Any],
    legacy_secret_key_section: dict[str, Any],
) -> AuthConfig:
    secret_key_dir = _to_str(section.get("secret_key_dir"), "") or _to_str(
        section.get("secret_dir"),
        "",
    )
    active_key_id = _to_str(section.get("active_key_id"), "")

    if legacy_secret_key_section:
        secret_key_dir = secret_key_dir or _to_str(
            legacy_secret_key_section.get("secret_key_dir"),
            _to_str(legacy_secret_key_section.get("secret_dir"), "secret_keys"),
        )
        active_key_id = active_key_id or _to_str(
            legacy_secret_key_section.get("active_key_id"),
            "",
        )

    cfg = AuthConfig(
        secret_key_dir=secret_key_dir or "secret_keys",
        active_key_id=active_key_id,
    )
    cfg = AuthConfig(
        secret_key_dir=os.getenv("API_SECRET_KEY_DIR", cfg.secret_key_dir),
        active_key_id=os.getenv("API_SECRET_KEY_ACTIVE_KEY_ID", cfg.active_key_id),
    )

    enabled_override_raw = os.getenv("API_SECRET_KEY_ENABLED")
    if enabled_override_raw is not None and not _to_bool(enabled_override_raw, True):
        cfg = AuthConfig(secret_key_dir=cfg.secret_key_dir, active_key_id="")

    return cfg


def _build_project_config(settings: dict[str, Any]) -> ProjectConfig:
    internal_section = _as_dict(settings.get("internal_assertion"))
    runtime_section = _as_dict(settings.get("runtime"))
    auth_section = _as_dict(settings.get("auth"))
    legacy_secret_key_section = _as_dict(settings.get("secret_key"))

    internal_cfg = InternalAssertionConfig(
        enabled=_to_bool(internal_section.get("enabled"), False),
        required=_to_bool(internal_section.get("required"), False),
        header_name=_to_str(
            internal_section.get("header_name"),
            HEADER_INTERNAL_ASSERTION,
        ),
        clock_skew_sec=_to_int(internal_section.get("clock_skew_sec"), 30),
        replay_ttl_sec=_to_int(internal_section.get("replay_ttl_sec"), 15),
        enforce_path_binding=_to_bool(
            internal_section.get("enforce_path_binding"),
            False,
        ),
    )

    # 环境变量优先覆盖，便于部署时按实例开关策略切换。
    internal_cfg = InternalAssertionConfig(
        enabled=_env_bool("API_INTERNAL_ASSERTION_ENABLED", internal_cfg.enabled),
        required=_env_bool("API_INTERNAL_ASSERTION_REQUIRED", internal_cfg.required),
        header_name=os.getenv("API_INTERNAL_ASSERTION_HEADER", internal_cfg.header_name),
        clock_skew_sec=_env_int(
            "API_INTERNAL_ASSERTION_CLOCK_SKEW_SEC",
            internal_cfg.clock_skew_sec,
        ),
        replay_ttl_sec=_env_int(
            "API_INTERNAL_ASSERTION_REPLAY_TTL_SEC",
            internal_cfg.replay_ttl_sec,
        ),
        enforce_path_binding=_env_bool(
            "API_INTERNAL_ASSERTION_ENFORCE_PATH",
            internal_cfg.enforce_path_binding,
        ),
    )

    runtime_cfg = _build_runtime_config(runtime_section, legacy_secret_key_section)
    auth_cfg = _build_auth_config(auth_section, legacy_secret_key_section)

    return ProjectConfig(
        redis=_build_redis_config(_as_dict(settings.get("redis"))),
        internal_assertion=internal_cfg,
        runtime=runtime_cfg,
        auth=auth_cfg,
    )


def _build_secret_key_service(
    project_root: Path,
    params: SecretKeyStartupParams,
) -> SecretKeyService | None:
    active_key_id = params.active_key_id.strip()
    if not active_key_id:
        return None

    secret_dir = Path(params.secret_key_dir)
    if not secret_dir.is_absolute():
        secret_dir = project_root / secret_dir

    owner = ServiceKeyOwner(
        entity_type=params.entity_type,
        entity_id=params.entity_id,
        entity_name=params.entity_name,
        instance_id=params.instance_id,
        instance_name=params.instance_name,
    ).normalized()

    return SecretKeyService.from_secret_dir(
        owner=owner,
        active_key_id=active_key_id,
        secret_dir=secret_dir,
        catalog=None,
        mysql_client=None,
    )


async def _default_echo_handler(req: InMemoryGrpcRequest) -> InMemoryGrpcResponse:
    return InMemoryGrpcResponse(
        status_code=200,
        payload=req.payload,
        headers={"x-api-service": "ok"},
    )


def _build_redis_manager(cfg: ProjectConfig) -> RedisManager | None:
    redis_cfg = cfg.redis
    if redis_cfg is None:
        return None

    has_hosts = bool(redis_cfg.HOSTS)
    has_single_endpoint = bool(redis_cfg.HOST and redis_cfg.PORT is not None)
    if not has_hosts and not has_single_endpoint:
        return None

    return RedisManager(cfg)


async def run_service(settings_path: Path) -> None:
    project_root = Path(__file__).resolve().parent
    settings = _read_settings_file(settings_path)
    cfg = _build_project_config(settings)
    secret_key_params = cfg.build_secret_key_startup_params(default_entity_id="api_service")

    grpc_server = GrpcServerAdapter(address="0.0.0.0:50052", service_name="api_service")
    grpc_server.add_unary_handler("/api_service.v1.Internal/Echo", _default_echo_handler)

    assertion_cfg = (
        cfg.internal_assertion.normalized()
        if cfg.internal_assertion is not None
        else InternalAssertionConfig().normalized()
    )
    if assertion_cfg.enabled and not secret_key_params.active_key_id:
        raise ValueError("auth.active_key_id is required when internal assertion is enabled")

    secret_key_service = (
        _build_secret_key_service(project_root, secret_key_params)
        if assertion_cfg.enabled
        else None
    )
    redis_manager = _build_redis_manager(cfg)
    runtime_metrics = AuthRuntimeMetrics()

    async def _on_boot() -> None:
        if redis_manager is None:
            return
        try:
            await redis_manager.connect()
            print("api_service redis connected")
        except Exception as exc:  # noqa: BLE001
            print(
                "api_service redis init failed, replay protection falls back to memory",
                {"error": str(exc)},
            )

    async def _on_shutdown() -> None:
        if redis_manager is None:
            return
        with contextlib.suppress(Exception):
            await redis_manager.disconnect()

    # 在启动前装配断言验签链路，确保服务启动即具备入站验证能力。
    wire_internal_assertion_verification(
        grpc_server=grpc_server,
        secret_key_service=secret_key_service,
        cfg=cfg,
        redis_manager=redis_manager,
        runtime_metrics=runtime_metrics,
    )

    app = ServiceApp(
        lifecycle=HookLifecycle(on_boot=_on_boot, on_shutdown=_on_shutdown),
        grpc_server=grpc_server,
    )

    await app.run()
    print(
        "api_service started",
        {
            "address": grpc_server.address,
            "internal_assertion_enabled": assertion_cfg.enabled,
            "internal_assertion_required": assertion_cfg.required,
            "internal_assertion_header": assertion_cfg.header_name,
            "secret_key_enabled": bool(secret_key_params.active_key_id),
        },
    )

    try:
        await asyncio.Event().wait()
    finally:
        print("api_service runtime metrics", runtime_metrics.snapshot())
        await app.stop()


def main() -> None:
    args = _build_parser().parse_args()
    settings_path = Path(args.settings)
    if not settings_path.is_absolute():
        settings_path = Path(__file__).resolve().parent / settings_path

    try:
        asyncio.run(run_service(settings_path))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
