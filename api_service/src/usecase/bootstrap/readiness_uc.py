from __future__ import annotations

from time import time

from src.models.auth.bootstrap import (
    BootstrapAuthRequest,
    BootstrapAuthResult,
    ChallengeRequest,
    SignedChallengeResponse,
)
from src.services.auth.bootstrap_cli import BootstrapClient


class ReadinessUsecase:
    """启动阶段认证就绪编排：stage 检查 -> challenge -> 签名提交。"""

    def __init__(self, bootstrap_client: BootstrapClient):
        self.bootstrap_client = bootstrap_client

    async def execute(self, challenge_req: ChallengeRequest) -> BootstrapAuthResult | None:
        principal_id = f"{challenge_req.entity_type}:{challenge_req.entity_id}"
        stage = await self.bootstrap_client.get_bootstrap_stage({"principal_id": principal_id})
        if stage == "ready":
            now = time()
            return BootstrapAuthResult(
                stage="ready",
                identity=None,
                session=None,
                tokens=None,
                active_comm_key_id=challenge_req.key_id,
                issued_at=now,
                expires_at=now,
            )

        challenge = await self.bootstrap_client.init_challenge(challenge_req)
        signed = SignedChallengeResponse(
            challenge_id=challenge.challenge_id,
            key_id=challenge.key_id,
            signature_algorithm="ed25519",
            signature="memory-signed",
            signed_at=time(),
        )
        return await self.bootstrap_client.authenticate_bootstrap(
            BootstrapAuthRequest(
                challenge=challenge,
                signed=signed,
                scopes=["internal.invoke"],
                role="service",
                require_downstream_token=True,
            )
        )
