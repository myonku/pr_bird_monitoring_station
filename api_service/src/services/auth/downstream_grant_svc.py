from src.models.auth.auth import DownstreamAccessGrant
from src.models.auth.auth_contract import DownstreamGrantRequest
from src.services.auth.auth_gateway_authority import IAuthGatewayAuthorityClient


class DownstreamGrantService:
    def __init__(self, authority_client: IAuthGatewayAuthorityClient):
        self._authority_client = authority_client

    async def issue_downstream_grant(
        self,
        req: DownstreamGrantRequest,
    ) -> DownstreamAccessGrant:
        return await self._authority_client.issue_downstream_grant(req)
