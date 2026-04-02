# Edge Workflow Spec

Version: 1.0.0

## 1. Scope

This document defines the edge business workflow for bird monitoring runtime.

In scope:
- Capture trigger and image ingestion flow.
- Decision and optional local inference flow.
- Unified business upload channel.
- Offline SQLite spool and resumable upload flow.

Out of scope:
- Authentication implementation details (kept in EDGE_AUTH_DESIGN_SPEC.md).
- Model training pipeline details.

## 2. End-to-End Flow

1. Capture stage:
- Trigger source is PIR (production) or mock capture (development).
- Capture module outputs `CaptureContext` and `ImagePayload`.

2. Decision-before-inference stage:
- Runtime status is sampled from:
- network readiness (upload healthcheck)
- device load snapshot (CPU/memory usage)
- Decision chooses:
- whether to execute local inference
- whether to upload immediately
- whether server assistance should be requested

3. Local inference stage (optional):
- Two-stage inference is used:
- detection -> crop -> classification
- Inference result and model signatures are attached to event metadata.

4. Delivery stage:
- Business payload always uses one HTTP upload channel.
- Auth workflow is isolated and not embedded in business pipeline logic.

5. Offline buffering stage:
- If upload is skipped by policy or upload request fails, event is written to SQLite spool.
- Spool database path defaults to `data/edge_spool.sqlite3`.

6. Resume stage:
- Sync worker checks connectivity and drains pending spool events in batches.
- Successful uploads are ACKed; failures are marked for retry.

## 3. Module Responsibilities

- `main.py`
- Creates concrete modules and wires dependencies.
- Runs pipeline loop and periodic spool draining.

- `src/ignitor/capture_module.py`
- `MockCaptureModule`: development/testing capture source.
- `PIRCameraCaptureModule`: Raspberry Pi PIR-triggered camera capture.

- `src/orchestration/decision_engine.py`
- Applies policy to runtime status and inference outputs.

- `src/orchestration/runtime_signal.py`
- Samples resource usage and builds runtime status input.

- `src/orchestration/pipeline.py`
- Orchestrates one event lifecycle.

- `src/orchestration/sqlite_spool.py`
- Local durable spool implementation over SQLite.

- `src/orchestration/sync_worker.py`
- Handles resumable upload from spool.

- `src/reasoner/*`
- Model loading and inference execution.

- `src/uploader/*`
- Unified business upload transport.

## 4. Data Channel Separation

Business and auth channels must remain isolated:
- Business modules only call uploader interfaces.
- Auth models/interfaces stay under auth-specific modules.
- No direct auth orchestration logic is embedded in edge business pipeline.

## 5. Configuration Baseline

Expected key sections in `settings.toml`:
- `[runtime]`
- `[capture]`
- `[decision_policy]`
- `[upload_http]`
- `[model_pack]`
- `[[model_pack_lightweight_candidates]]`

## 6. Evolution Rules

1. Keep pipeline steps explicit and single-directional.
2. Keep delivery path unified for both inferred and non-inferred events.
3. Keep offline durability local and deterministic (SQLite first).
4. Keep auth integration pluggable via dedicated auth interfaces.
5. Add new capture/inference backends via adapters, not by bloating orchestration modules.
