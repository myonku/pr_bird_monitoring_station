# 边缘端识别/上传服务

该分区当前采用本地双模型两阶段流程：

- 传感器触发捕拍
- 条件允许时执行本地推理（检测 -> 分类）
- 检测成功后先裁切目标区域，再进行分类
- 检测失败或无目标时提前退出分类
- 统一通过 HTTP 上传
- 上传失败写入本地待补传存储

## 当前模型布局（已切换）

边缘端不再依赖旧版统一模型协定配置块，改为本地模型目录扫描：

- model_pack/detection：仅保留 1 个检测模型文件
- model_pack/classification：仅保留 1 个分类模型文件

约束：每个 task 目录必须且仅有一个模型文件，否则启动时报错。

训练侧产物文件名保持原样即可。边缘端加载器会根据文件名与扩展名推导：

- task（detection / classification）
- framework（yolo / pytorch）
- model_name（如 yolo11n、mobilenet_v3_large、convnext_base）
- format（onnx / torchscript / custom）

说明：目前边缘端仅使用 lightweight 路径，tier 仅做兼容保留，不参与调度决策。

## 架构分层

- 捕拍层：ICaptureModule
- 模型加载层：IModelBundleLoader
  - 从 model_pack 自动发现 detection + classification 模型
  - 输出统一 LoadedModelBundle
- 推理层：IInferenceModule
  - 仅负责推理逻辑，不承担模型发现职责
  - 提供 detect / classify / infer_two_stage
- 编排层：EdgePipeline + DecisionEngine
- 上传层：IUploader + IHttpTransportClient（HTTP only）

## 配置文件

见 settings.toml，重点字段：

- [runtime]：设备 ID、本地 spool 参数
- [upload_http]：上传地址、健康检查地址、超时、token
- [decision_policy]：本地推理开关、置信度阈值、负载跳过策略
- [model_pack]：模型目录配置（root_dir / detection_dir / classification_dir）

## 训练侧与边缘侧参数对齐说明

你关心的“是否必须严格统一”可以分为两类：

必须严格一致（否则可能直接报错或结果严重偏移）：

- 模型文件与加载后端匹配：例如 PyTorch 权重不能按 YOLO 方式加载。
- 输入预处理规格：尺寸、通道顺序、归一化方式需与训练/导出时一致。
- 输出解释方式：检测框坐标语义、分类 logits/topk 解释必须一致。
- 类别索引映射：class id 到 class name 的顺序必须一致。

可在边缘侧独立调优（不影响模型可运行，但影响业务行为）：

- 置信度阈值（confidence_threshold）
- 服务端辅助策略（requires_server_assist 判定）
- 高负载跳过策略与上传策略

实践建议：

- 把“运行必须一致”的部分固化在模型加载器和预处理模块中。
- 把“业务可调参数”保留在 settings.toml 中做策略调参。

## 运行

- 单次执行：
  python main.py --settings settings.toml
- 持续运行：
  python main.py --settings settings.toml --loop --interval-sec 1.0