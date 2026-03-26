# 边缘端识别/上传服务

该分区已按新需求重写为双模型两阶段骨架：

- 传感器触发捕拍
- 条件允许时执行本地推理（检测 -> 分类）
- 检测失败或无目标时可提前退出分类
- 统一通过 HTTP 上传
- 上传失败时写入本地待补传存储

## 架构分层

- 捕拍层：ICaptureModule
- 模型加载层：IModelBundleLoader
	- 一次加载检测模型与分类模型
	- 输出统一 LoadedModelBundle
- 推理层：IInferenceModule
	- 只负责推理逻辑，不承担模型加载职责
	- 提供 detect / classify / infer_two_stage
- 编排层：EdgePipeline + DecisionEngine
- 上传层：IUploader + IHttpTransportClient（HTTP only）

## 模型协定（训练侧 <-> 边缘侧）

模型协定在 settings.toml 中体现为：

- [model_contract]
	- 包版本、协定版本、导出信息
- [model_contract_detection]
	- 检测模型规格（框架、格式、输入尺寸、阈值、路径）
- [model_contract_classification]
	- 分类模型规格（框架、格式、标签集、路径）

边缘端通过同一协定一次加载 detection + classification 两个模型。

详细规范见 MODEL_CONTRACT_SPEC.md。

## 配置文件

见 settings.toml，重点字段：

- [runtime]：设备 ID、本地 spool 参数
- [upload_http]：上传地址、健康检查地址、超时、token
- [decision_policy]：本地推理开关、置信度阈值、负载跳过策略
- [model_contract*]：双模型协定

## 运行

- 单次执行：
	python main.py --settings settings.toml
- 持续运行：
	python main.py --settings settings.toml --loop --interval-sec 1.0