from __future__ import annotations

from collections.abc import Awaitable, Callable


class GrpcServerAdapter:
    """普通服务模块 gRPC 入站适配器骨架（仅负责启动/停止与服务注册）。"""

    def __init__(self, address: str = "0.0.0.0:50052"):
        self.address = address
        self._register_hooks: list[Callable[[], None]] = []
        self._started = False

    def add_service_registration(self, register_hook: Callable[[], None]) -> None:
        self._register_hooks.append(register_hook)

    async def start(self) -> None:
        for register in self._register_hooks:
            register()
        self._started = True

    async def stop(self) -> None:
        self._started = False


class UnaryInterceptorChain:
    """gRPC unary 拦截器链容器骨架。"""

    def __init__(self):
        self.interceptors: list[Callable[..., Awaitable[object]]] = []

    def add(self, interceptor: Callable[..., Awaitable[object]]) -> None:
        self.interceptors.append(interceptor)
