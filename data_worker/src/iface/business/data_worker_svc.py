from abc import ABC


class IDataWorkerService(ABC):
    """数据处理模块的唯一业务流水线接口。负责处理边缘端上传事件数据，
    完成从原始数据到最终结果的全流程处理。"""
    