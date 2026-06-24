from beanie import init_beanie
from pymongo import AsyncMongoClient

from src.models.sys.config import ProjectConfig
from src.utils.circuit_breaker import CircuitBreaker, CircuitOpenError


class MongoDBClient:
    """MongoDB 连接管理器，集成 Beanie ODM"""

    def __init__(self, cfg: ProjectConfig):
        self.cfg = cfg
        self.client: AsyncMongoClient | None = None
        self.is_initialized: bool = False
        if not cfg.mongo:
            raise RuntimeError("Mongo配置初始化失败")
        self.circuit = CircuitBreaker("mongo", cfg.mongo.CIRCUITBREAKER)

    async def is_connected(self) -> bool:
        """检查连接状态"""
        try:
            if self.client is None:
                return False

            async def _ping() -> dict:
                # server_info 本身就是一次简单的健康检查
                assert self.client is not None
                return await self.client.server_info()

            await self.circuit.call(_ping)
            return True
        except CircuitOpenError:
            # 熔断已打开，视为未连接
            return False
        except Exception:
            return False

    async def connect(self, document_models: list | None = None):
        """连接数据库并初始化 Beanie"""
        if not self.cfg.mongo:
            raise ConnectionError("Mongo配置初始化失败")
        print(f"正在连接MongoDB服务: {self.cfg.mongo.mongo_uri}")
        self.client = AsyncMongoClient(
            self.cfg.mongo.mongo_uri, serverSelectionTimeoutMS=3000
        )
        if document_models:
            await init_beanie(
                database=self.client[self.cfg.mongo.DATABASE],
                document_models=document_models,
            )
        self.is_initialized = True
        print(f"已连接至Mongo数据库服务[{self.cfg.mongo.DATABASE}]，Beanie 初始化已完成")

    async def disconnect(self):
        """关闭连接"""
        if self.client:
            print("正在关闭MongoDB连接")
            await self.client.close()
            self.is_initialized = False
