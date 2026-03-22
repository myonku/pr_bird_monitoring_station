from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class InMemoryGrpcRequest:
    method: str
    payload: bytes
    headers: dict[str, str]


@dataclass(slots=True)
class InMemoryGrpcResponse:
    status_code: int
    payload: bytes
    headers: dict[str, str]


_INMEMORY_SERVERS_BY_ENDPOINT: dict[str, "GrpcServerAdapter"] = {}


def resolve_inmemory_server(endpoint: str) -> "GrpcServerAdapter" | None:
    return _INMEMORY_SERVERS_BY_ENDPOINT.get(endpoint)


class GrpcServerAdapter:
    """普通服务模块 gRPC 入站适配器骨架（仅负责启动/停止与服务注册）。"""

    def __init__(self, address: str = "0.0.0.0:50052", service_name: str = "api_service"):
        self.address = address
        self.service_name = service_name
        self._register_hooks: list[Callable[[], None]] = []
        self._started = False
        self._handlers: dict[str, Callable[[InMemoryGrpcRequest], Awaitable[InMemoryGrpcResponse]]] = {}
        self._interceptors = UnaryInterceptorChain()

    def add_service_registration(self, register_hook: Callable[[], None]) -> None:
        self._register_hooks.append(register_hook)

    def add_unary_handler(
        self,
        method: str,
        handler: Callable[[InMemoryGrpcRequest], Awaitable[InMemoryGrpcResponse]],
    ) -> None:
        self._handlers[method] = handler

    def add_unary_interceptor(self, interceptor: Callable[..., Awaitable[object]]) -> None:
        self._interceptors.add(interceptor)

    async def start(self) -> None:
        if self._started:
            return
        for register in self._register_hooks:
            register()
        _INMEMORY_SERVERS_BY_ENDPOINT[self.address] = self
        self._started = True

    async def stop(self) -> None:
        _INMEMORY_SERVERS_BY_ENDPOINT.pop(self.address, None)
        self._started = False

    async def handle_unary(
        self,
        method: str,
        payload: bytes,
        headers: dict[str, str] | None = None,
    ) -> InMemoryGrpcResponse:
        if not self._started:
            raise RuntimeError(f"grpc server {self.service_name} is not started")
        handler = self._handlers.get(method)
        if handler is None:
            return InMemoryGrpcResponse(
                status_code=404,
                payload=f"method {method} not found".encode("utf-8"),
                headers={},
            )

        req = InMemoryGrpcRequest(method=method, payload=payload, headers=headers or {})

        async def _final_handler() -> InMemoryGrpcResponse:
            return await handler(req)

        chained = _final_handler
        for interceptor in reversed(self._interceptors.interceptors):
            previous = chained

            async def _wrapped(
                it=interceptor,
                nxt=previous,
                request=req,
                meth=method,
            ) -> InMemoryGrpcResponse:
                result = await it(request, meth, nxt)
                if isinstance(result, InMemoryGrpcResponse):
                    return result
                return await nxt()

            chained = _wrapped

        return await chained()


class UnaryInterceptorChain:
    """gRPC unary 拦截器链容器骨架。"""

    def __init__(self):
        self.interceptors: list[Callable[..., Awaitable[object]]] = []

    def add(self, interceptor: Callable[..., Awaitable[object]]) -> None:
        self.interceptors.append(interceptor)
