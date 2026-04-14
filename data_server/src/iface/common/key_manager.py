from abc import ABC, abstractmethod

from src.models.commsec.commsec import (
    LocalPrivateKeyRef,
    PublicKeyLookupRequest,
    PublicKeyLookupResult,
    ServicePublicKeyRecord,
)


class IKeyManager(ABC):
    """本地密钥管理和公钥目录查询接口，提供本地公私钥访问和目录查询功能。"""

    @abstractmethod
    async def get_public_key(self) -> ServicePublicKeyRecord:
        """获取本地服务当前使用的公钥记录。"""
        raise NotImplementedError

    @abstractmethod
    async def get_private_key_ref(self) -> LocalPrivateKeyRef:
        """获取活动的本地私钥引用。"""
        raise NotImplementedError

    @abstractmethod
    async def lookup_public_key(
        self,
        req: PublicKeyLookupRequest,
    ) -> PublicKeyLookupResult:
        """根据 key_id, entity_id 或 owner 维度查找目录密钥。"""
        raise NotImplementedError

