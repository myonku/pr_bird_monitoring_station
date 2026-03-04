from edge_server.src.interface import ITransportClient, IUploader
from models.models import EdgeEvent


class UnifiedUploader(IUploader):
    """
    可以内部切换 Kafka/HTTP/gRPC；
    对 pipeline 暴露统一 upload(event)。
    """

    def __init__(self, transport_client: ITransportClient):
        self.client = transport_client

    def upload(self, event: EdgeEvent) -> bool:
        # 序列化后通过统一通道发送
        # 后端根据字段自行判断是否需要云端识别
        # event.requires_server_assist + event.local_inference + 原图
        try:
            payload = {
                "event_id": event.event_id,
                "trace_id": event.trace_id,
                "requires_server_assist": event.requires_server_assist,
                "context": event.context.__dict__,
                "local_inference": (
                    event.local_inference.__dict__ if event.local_inference else None
                ),
                "metadata": event.metadata,
                # image bytes 应按协议处理（二进制/对象存储引用）
            }
            return self.client.send(payload, image_bytes=event.image.bytes_data)
        except Exception:
            return False

    def is_connection_ready(self) -> bool:
        return self.client.healthcheck()
