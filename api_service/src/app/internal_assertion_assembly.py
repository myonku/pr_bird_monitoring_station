from __future__ import annotations

from src.adapters.grpc.server_adapter import GrpcServerAdapter
from src.models.sys.config import InternalAssertionConfig, ProjectConfig
from src.repo.redis_store import RedisManager
from src.services.auth.internal_assertion_verifier import IInternalAssertionVerifier
from src.services.auth.internal_assertion_verifier_svc import InternalAssertionVerifier
from src.services.auth.runtime_metrics import AuthRuntimeMetrics
from src.services.commsec.secret_key_svc import SecretKeyService


def wire_internal_assertion_verification(
    grpc_server: GrpcServerAdapter,
    secret_key_service: SecretKeyService | None,
    cfg: ProjectConfig | None,
    redis_manager: RedisManager | None = None,
    runtime_metrics: AuthRuntimeMetrics | None = None,
) -> IInternalAssertionVerifier | None:
    """装配 api_service gRPC 入站内部断言验签能力。"""

    internal_cfg = _resolve_internal_assertion_config(cfg)
    if not internal_cfg.enabled:
        return None

    if secret_key_service is None:
        raise ValueError("secret key service is required when internal assertion is enabled")

    verifier = InternalAssertionVerifier(
        secret_key_service=secret_key_service,
        redis_manager=redis_manager,
        service_name=grpc_server.service_name,
        config=internal_cfg,
        runtime_metrics=runtime_metrics,
    )
    grpc_server.add_internal_assertion_interceptor(
        verifier=verifier,
        config=internal_cfg,
    )
    return verifier


def _resolve_internal_assertion_config(cfg: ProjectConfig | None) -> InternalAssertionConfig:
    if cfg is None or cfg.internal_assertion is None:
        return InternalAssertionConfig().normalized()
    return cfg.internal_assertion.normalized()
