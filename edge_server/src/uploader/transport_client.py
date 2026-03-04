from edge_server.src.interface import ITransportClient


class TransportClient(ITransportClient):
    """边缘端上传模块的传输客户端，负责将边缘事件数据发送到后端服务器"""
    def __init__(self, transport_client):
        self.transport_client = transport_client