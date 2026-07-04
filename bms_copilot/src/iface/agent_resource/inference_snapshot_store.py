from __future__ import annotations

from typing import Protocol

from src.models.agent.snapshot import InferenceResultSnapshot


class IInferenceSnapshotStore(Protocol):
    async def save_snapshot(self, snapshot: InferenceResultSnapshot) -> None: ...

    async def list_by_session(
        self, session_id: str, limit: int = 20
    ) -> list[InferenceResultSnapshot]: ...