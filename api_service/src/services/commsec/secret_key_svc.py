from src.models.auth.bootstrap import PublicKeyLookupResult
from src.models.commsec.commsec import (
    LocalPrivateKeyRef,
    ServiceKeyOwner,
    ServicePublicKeyRecord,
)


class SecretKeyService:
    """密钥服务：本地私钥引用 + 全局公钥目录查询。"""

    def __init__(self):
        ...

    async def get_public_key(self, ctx: object) -> ServicePublicKeyRecord:
        ...

    async def get_private_key_ref(self, ctx: object) -> LocalPrivateKeyRef:
        ...

    async def get_public_key_by_key_id(
        self, ctx: object, key_id: str
    ) -> PublicKeyLookupResult:
        ...

    async def get_public_keys_by_owner(
        self, ctx: object, owner: ServiceKeyOwner
    ) -> list[ServicePublicKeyRecord]:
        ...
