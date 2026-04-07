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
from src.app.forwarded_auth_assembly import wire_forwarded_auth_revalidation
from src.app.lifecycle import HookLifecycle
from src.models.sys.config import (
    AuthConfig,
    ProjectConfig,
    RedisConfig,
    RuntimeConfig,
)
from src.repo.redis_store import RedisManager
from src.services.auth.auth_authority import IAuthAuthorityClient
from src.services.auth.forwarded_auth_verifier import IForwardedAuthVerifier
from src.services.auth.forwarded_auth_verifier_svc import (
    AuthorityBackedForwardedAuthVerifier,
)
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
    runtime_section = _as_dict(settings.get("runtime"))
    auth_section = _as_dict(settings.get("auth"))
    legacy_secret_key_section = _as_dict(settings.get("secret_key"))

    runtime_cfg = _build_runtime_config(runtime_section, legacy_secret_key_section)
    auth_cfg = _build_auth_config(auth_section, legacy_secret_key_section)

    return ProjectConfig(
        redis=_build_redis_config(_as_dict(settings.get("redis"))),
        runtime=runtime_cfg,
        auth=auth_cfg,
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


def _build_forwarded_auth_verifier(
    settings: dict[str, Any],
    authority_client: IAuthAuthorityClient | None,
    service_name: str,
) -> IForwardedAuthVerifier | None:
    section = _as_dict(settings.get("forwarded_auth"))
    enabled = _env_bool(
        "API_FORWARDED_AUTH_ENABLED",
        _to_bool(section.get("enabled"), False),
    )
    if not enabled:
        return None

    if authority_client is None:
        raise ValueError(
            "forwarded_auth.enabled=true requires a provided authority client instance"
        )

    return AuthorityBackedForwardedAuthVerifier(
        authority_client=authority_client,
        service_name=service_name,
    )


async def run_service(
    settings_path: Path,
    authority_client: IAuthAuthorityClient | None = None,
) -> None:
    settings = _read_settings_file(settings_path)
    cfg = _build_project_config(settings)

    grpc_server = GrpcServerAdapter(address="0.0.0.0:50052", service_name="api_service")
    grpc_server.add_unary_handler("/api_service.v1.Internal/Echo", _default_echo_handler)
    redis_manager = _build_redis_manager(cfg)
    runtime_metrics = AuthRuntimeMetrics()
    forwarded_auth_verifier = _build_forwarded_auth_verifier(
        settings=settings,
        authority_client=authority_client,
        service_name=grpc_server.service_name,
    )

    async def _on_boot() -> None:
        if redis_manager is None:
            return
        try:
            await redis_manager.connect()
            print("api_service redis connected")
        except Exception as exc:  # noqa: BLE001
            print(
                "api_service redis init failed",
                {"error": str(exc)},
            )

    async def _on_shutdown() -> None:
        if redis_manager is None:
            return
        with contextlib.suppress(Exception):
            await redis_manager.disconnect()

    wire_forwarded_auth_revalidation(
        grpc_server=grpc_server,
        verifier=forwarded_auth_verifier,
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
            "forwarded_auth_enabled": forwarded_auth_verifier is not None,
            "forwarded_auth_mode": (
                "authority_backed" if forwarded_auth_verifier is not None else "disabled"
            ),
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
