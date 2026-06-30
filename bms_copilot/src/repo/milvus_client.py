import asyncio

from pymilvus import MilvusClient
from src.models.sys.config import MilvusConfig, ProjectConfig
from src.utils.circuit_breaker import CircuitBreaker, CircuitOpenError


class Milvus:
    """Milvus SDK 上层封装，提供基本功能接口"""

    def __init__(self, cfg: ProjectConfig) -> None:
        self.cfg = cfg
        self.client: MilvusClient | None = None
        milvus_cfg = (cfg.milvus or MilvusConfig()).normalized()
        self.milvus_cfg = milvus_cfg
        self.circuit = CircuitBreaker("milvus", milvus_cfg.CIRCUITBREAKER)

    def _build_uri(self) -> str:
        if self.milvus_cfg.URI:
            return self.milvus_cfg.URI
        return f"http://{self.milvus_cfg.HOST}:{self.milvus_cfg.PORT}"

    async def is_connected(self) -> bool:
        """检查连接状态。"""
        try:
            if self.client is None:
                return False

            async def _ping() -> object:
                assert self.client is not None
                return await asyncio.to_thread(
                    self.client.list_collections,
                    db_name=self.milvus_cfg.DB_NAME,
                )

            await self.circuit.call(_ping)
            return True
        except CircuitOpenError:
            return False
        except Exception:
            return False

    def connect(self) -> None:
        """连接 Milvus 并创建客户端实例。"""
        if self.client is not None:
            return
        print(f"正在连接Milvus服务: {self._build_uri()}")
        self.client = MilvusClient(
            uri=self._build_uri(),
            token=self.milvus_cfg.TOKEN or "",
            db_name=self.milvus_cfg.DB_NAME,
        )
        print(f"已连接至Milvus服务[{self.milvus_cfg.DB_NAME}]")

    def disconnect(self) -> None:
        """关闭连接。"""
        if self.client is not None:
            print("正在关闭Milvus连接")
            self.client.close()
            self.client = None
