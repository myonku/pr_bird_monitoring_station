from __future__ import annotations

from src.models.sys.config import ProjectConfig, RuntimeConfig, SecretKeyStartupParams
from src.services.common.secret_key_svc import SecretKeyService


def resolve_startup_security_materials(
    *,
    config: ProjectConfig,
    runtime_cfg: RuntimeConfig,
    default_entity_id: str = "bms_copilot",
) -> tuple[SecretKeyStartupParams, SecretKeyService | None]:
    startup_params = config.build_secret_key_startup_params(
        default_entity_id=default_entity_id,
    )
    if runtime_cfg.run_mode == "no_auth":
        return startup_params, None

    secret_key_service = SecretKeyService.from_startup_params(params=startup_params)
    return startup_params, secret_key_service
