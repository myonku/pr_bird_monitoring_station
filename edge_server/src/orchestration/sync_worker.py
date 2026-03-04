import time
from edge_server.src.interface import IUploader, ISpoolStorage


class SyncWorker:
    """负责将 SpoolStorage 中待上传的事件批量上传到后端，确保数据最终一致性。"""
    def __init__(
        self,
        uploader: IUploader,
        spool: ISpoolStorage,
        batch_size: int = 20,
        interval_sec: float = 3.0,
    ):
        self.uploader = uploader
        self.spool = spool
        self.batch_size = batch_size
        self.interval_sec = interval_sec
        self._running = True

    def stop(self):
        self._running = False

    def run_forever(self):
        while self._running:
            if not self.uploader.is_connection_ready():
                time.sleep(self.interval_sec)
                continue

            batch = list(self.spool.peek_batch(self.batch_size))
            if not batch:
                time.sleep(self.interval_sec)
                continue

            for record_id, event in batch:
                ok = self.uploader.upload(event)
                if ok:
                    self.spool.ack(record_id)
                else:
                    self.spool.mark_retry(record_id, "upload_failed")
                    break
