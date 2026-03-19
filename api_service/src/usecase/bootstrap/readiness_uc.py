from __future__ import annotations

from src.models.auth.bootstrap import BootstrapAuthResult, ChallengeRequest
from src.services.auth.bootstrap_cli import BootstrapClient


class ReadinessUsecase:
    """启动阶段认证就绪编排：stage 检查 -> challenge -> 签名提交。"""

    def __init__(self, bootstrap_client: BootstrapClient):
        self.bootstrap_client = bootstrap_client

    async def execute(self, challenge_req: ChallengeRequest) -> BootstrapAuthResult | None:
        ...
