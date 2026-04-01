# Edge-Server Model Contract Spec

> Deprecated: this document describes the historical model_contract settings design.
> Current edge runtime uses model_pack directory discovery (see README.md).

Version: 1.0.0

This document defines a shared contract between model_trainer outputs and edge_server runtime consumption.

## 1. Contract Shape

The contract is represented by three sections in `settings.toml`:

- `[model_contract]`
- `[model_contract_detection]`
- `[model_contract_classification]`

`edge_server/src/models/config.py` maps these fields to:

- `EdgeModelContract`
- `ModelArtifactContract` (detection)
- `ModelArtifactContract` (classification)

## 2. Required Fields

### [model_contract]

- `contract_version` (string): schema version.
- `package_version` (string): model package version distributed to edge.
- `exported_at_ms` (int): Unix timestamp in milliseconds.
- `exported_by` (string): producing module, usually `model_trainer`.
- `notes` (string, optional): free-form notes.

### [model_contract_detection]

- `artifact_id` (string)
- `task` (must be `detection`)
- `tier` (`lightweight` | `standard`)
- `framework` (string)
- `model_name` (string)
- `format` (`onnx` | `tflite` | `torchscript` | `openvino` | `custom`)
- `model_version` (string)
- `artifact_path` (string, local path on edge)
- `labels` (string array)
- `input_size` ([width, height])
- `score_threshold` (float)
- `nms_iou_threshold` (float)
- `topk` (int)
- `checksum_sha256` (string, optional)

### [model_contract_classification]

- `artifact_id` (string)
- `task` (must be `classification`)
- `tier` (`lightweight` | `standard`)
- `framework` (string)
- `model_name` (string)
- `format` (`onnx` | `tflite` | `torchscript` | `openvino` | `custom`)
- `model_version` (string)
- `artifact_path` (string, local path on edge)
- `labels` (string array)
- `input_size` ([width, height])
- `score_threshold` (float, optional for classification)
- `nms_iou_threshold` (float, optional for classification)
- `topk` (int)
- `checksum_sha256` (string, optional)

## 3. Runtime Rules

1. Edge must load both detection and classification artifacts together.
2. Detection task mismatch or classification task mismatch must fail startup.
3. Inference order is fixed: detection first, classification second.
4. If detection fails or detects no target, classification must not execute.
5. Upload payload should include contract and package versions for traceability.

## 4. Producer Responsibilities (model_trainer)

1. Export the two artifacts as one package version.
2. Fill all required fields accurately.
3. Ensure label ordering is deterministic and consistent with training.
4. Provide checksum when available.

## 5. Consumer Responsibilities (edge_server)

1. Validate required fields before loading.
2. Validate task values (`detection` and `classification`).
3. Keep local fallback package for rollback.
4. Report `package_version` and model versions in event metadata.
