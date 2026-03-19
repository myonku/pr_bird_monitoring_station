from __future__ import annotations

from typing import Any


class ServiceApp:
    """普通服务模块应用入口：统一管理 lifecycle + grpc server。"""

    def __init__(self, lifecycle: Any, grpc_server: Any):
        self.lifecycle = lifecycle
        self.grpc_server = grpc_server

    async def run(self) -> None:
        await self.lifecycle.boot()
        await self.grpc_server.start()

    async def stop(self) -> None:
        await self.grpc_server.stop()
        await self.lifecycle.shutdown()
