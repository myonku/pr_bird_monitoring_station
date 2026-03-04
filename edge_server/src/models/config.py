from dataclasses import dataclass


@dataclass
class EdgeServerConfig:
    """边缘服务器配置类，包含捕拍模块、推理模块和其他相关配置项"""
    capture_module: str = "default_capture"
    inference_module: str = "default_inference"
    device_id: str = "edge_device_001"
    # 其他配置项，如日志级别、上传策略等