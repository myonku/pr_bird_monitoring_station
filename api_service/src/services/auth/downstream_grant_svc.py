from __future__ import annotations

from time import time

from src.models.auth.auth import DownstreamAccessGrant
from src.models.auth.auth_contract import DownstreamGrantRequest


class DownstreamGrantService:
    def __init__(self):
        pass

    async def issue_downstream_grant(
        self,
        req: DownstreamGrantRequest,
    ) -> DownstreamAccessGrant:
        if req is None:
            raise ValueError("downstream grant request is None")
        if not req.identity.principal_id:
            raise ValueError("identity principal_id is required")
        if not req.target_service:
            raise ValueError("target_service is required")

        now = time()
        ttl = req.ttl_sec if req.ttl_sec > 0 else 120
        return DownstreamAccessGrant(
            gateway_id=req.identity.gateway_id,
            source_service=req.identity.source_service,
            target_service=req.target_service,
            session_id=req.identity.session_id,
            token_id=req.identity.token_id,
            principal_id=req.identity.principal_id,
            binding_type=req.binding_type,
            scopes=list(req.identity.scopes),
            encryption_required=req.require_encryption,
            secure_channel_id=req.identity.secure_channel_id,
            cipher_suite=req.identity.cipher_suite,
            issued_at=now,
            expires_at=now + ttl,
        )
