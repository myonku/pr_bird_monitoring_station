from src.models.auth.bootstrap import (
    BootstrapAuthRequest,
    BootstrapAuthResult,
    BootstrapStage,
    ChallengePayload,
    ChallengeRequest,
)


class BootstrapClient:
    """冷启动认证流程服务。"""

    def __init__(self):
        ...

    async def init_challenge(self, ctx: object, req: ChallengeRequest) -> ChallengePayload:
        ...

    async def authenticate_bootstrap(
        self, ctx: object, req: BootstrapAuthRequest
    ) -> BootstrapAuthResult:
        ...

    async def get_bootstrap_stage(self, ctx: object) -> BootstrapStage:
        ...
