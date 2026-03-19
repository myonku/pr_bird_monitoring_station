from __future__ import annotations

from typing import Awaitable, Callable


class HookLifecycle:
    """可注入生命周期钩子，用于逐步替换为真实初始化逻辑。"""

    def __init__(
        self,
        on_boot: Callable[[], Awaitable[None]] | None = None,
        on_shutdown: Callable[[], Awaitable[None]] | None = None,
    ):
        self.on_boot = on_boot
        self.on_shutdown = on_shutdown

    async def boot(self) -> None:
        if self.on_boot is None:
            return
        await self.on_boot()

    async def shutdown(self) -> None:
        if self.on_shutdown is None:
            return
        await self.on_shutdown()
