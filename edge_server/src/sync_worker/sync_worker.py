import time
from dataclasses import dataclass

from src.iface.workflow_interface import ISpoolStorage
from src.iface.upload_interface import IEdgeEventUploadCoordinator


@dataclass(slots=True)
class SyncRoundResult:
    network_ready: bool
    pending_count: int
    uploaded_count: int
    failed_count: int


class SyncWorker:
    """负责将 SpoolStorage 中待上传的事件批量上传到后端，确保数据最终一致性。"""
    def __init__(
        self,
        upload_coordinator: IEdgeEventUploadCoordinator,
        spool: ISpoolStorage,
        batch_size: int = 20,
        interval_sec: float = 3.0,
    ):
        self.upload_coordinator = upload_coordinator
        self.spool = spool
        self.batch_size = batch_size
        self.interval_sec = interval_sec
        self._running = True

    def stop(self):
        self._running = False

    def drain_once(self) -> SyncRoundResult:
        if not self.upload_coordinator.is_upload_channel_ready():
            return SyncRoundResult(
                network_ready=False,
                pending_count=0,
                uploaded_count=0,
                failed_count=0,
            )

        batch = list(self.spool.peek_batch(self.batch_size))
        if not batch:
            return SyncRoundResult(
                network_ready=True,
                pending_count=0,
                uploaded_count=0,
                failed_count=0,
            )

        uploaded_count = 0
        failed_count = 0
        for record_id, event in batch:
            ok = self.upload_coordinator.upload_event(event)
            if ok:
                self.spool.ack(record_id)
                uploaded_count += 1
            else:
                self.spool.mark_retry(record_id, "upload_failed")
                failed_count += 1
                break

        return SyncRoundResult(
            network_ready=True,
            pending_count=len(batch),
            uploaded_count=uploaded_count,
            failed_count=failed_count,
        )

    def run_forever(self):
        while self._running:
            self.drain_once()
            time.sleep(self.interval_sec)
