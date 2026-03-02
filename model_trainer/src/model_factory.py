from __future__ import annotations
from typing import Literal

import timm
from torch import nn
from torchvision.models import MobileNet_V3_Large_Weights, mobilenet_v3_large
from torchvision.models.mobilenetv3 import MobileNetV3

SUPPORTED_MODELS = ("mobilenet_v3", "efficientnet_lite")


def build_model(
    model_name: Literal["mobilenet_v3", "efficientnet_lite"],
    num_classes: int,
    pretrained: bool,
) -> MobileNetV3 | nn.Module:
    """根据模型名称构建并返回一个 PyTorch 模型实例。"""
    model_key = model_name.lower().strip()
    if model_key == "mobilenet_v3":
        weights = MobileNet_V3_Large_Weights.DEFAULT if pretrained else None
        model = mobilenet_v3_large(weights=weights)
        classifier_head = model.classifier[3]
        if not isinstance(classifier_head, nn.Linear):
            raise TypeError("Unexpected classifier head type for mobilenet_v3_large")
        in_features = classifier_head.in_features
        model.classifier[3] = nn.Linear(in_features, num_classes)
        return model
    if model_key == "efficientnet_lite":
        model = timm.create_model(
            "efficientnet_lite0",
            pretrained=pretrained,
            num_classes=num_classes,
        )
        return model
    raise ValueError(f"unsupported model: {model_name}. choices={SUPPORTED_MODELS}")
