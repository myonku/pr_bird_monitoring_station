"""
边缘端上传接口集成测试。

模拟 edge_server 的完整上传流程（仅伪造请求，不实际跑边缘端硬件）：
1. 执行 bootstrap 获取认证令牌
2. 从 photos/ 目录读取测试图片
3. 构造不同场景的上传请求（已推理完成 / 需要后端辅助）
4. 经网关发送到 data_worker，验证响应

前置条件（已由脚本启动，或需手工启动）：
- certification_server (127.0.0.1:50051)
- gateway (127.0.0.1:8080)
- data_worker (127.0.0.1:50052)
"""
import base64
import hashlib
import json
import os
import sys
import time
import uuid
from pathlib import Path

# 添加 edge_server 到路径，复用其认证和加密模块
EDGE_SERVER_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(EDGE_SERVER_ROOT))

import urllib.request
import urllib.error

from src.utils.crypto_utils import CryptoUtils
from src.models.auth.bootstrap import BootstrapChallenge, SignedBootstrapProof

# ─── 配置 ───────────────────────────────────────────────────────────────────

GATEWAY_URL = "http://127.0.0.1:8080"
DEVICE_ID = "6a9d6b92-fe06-44ee-a607-7284e783f738"
KEY_ID = "626efa4f-0cd0-4e81-af6e-447b41bac8fc"
PHOTOS_DIR = EDGE_SERVER_ROOT / "tests" / "photos"
LABELS_PATH = EDGE_SERVER_ROOT / "model_pack" / "labels.txt"
SECRET_KEY_DIR = EDGE_SERVER_ROOT / "secret_keys"

# ─── 标签加载 ──────────────────────────────────────────────────────────────

def _load_labels(path: Path) -> dict[str, str]:
    """加载 labels.txt，返回 {class_id: species_name} 映射。"""
    labels: dict[str, str] = {}
    if not path.exists():
        return labels
    for line in path.read_text(encoding="utf-8").strip().splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            labels[parts[0]] = parts[1]
    return labels


LABELS = _load_labels(LABELS_PATH)


def _parse_class_id(filename: str) -> str | None:
    """从图片文件名解析类别 ID（如 '001-xxx.jpg' -> '001'）。"""
    parts = filename.split("-", 1)
    if parts and parts[0].isdigit():
        return parts[0]
    return None


def _species_name(class_id: str) -> str:
    return LABELS.get(class_id, f"unknown_class_{class_id}")


def _compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ─── HTTP 工具 ──────────────────────────────────────────────────────────────

class HttpClient:
    """轻量 HTTP 客户端。"""

    def __init__(self, base_url: str, timeout_sec: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.timeout_sec = timeout_sec

    def request_json(
        self,
        method: str,
        path: str,
        payload: dict | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict:
        url = f"{self.base_url}{path}"
        req_headers = {"Content-Type": "application/json"}
        if headers:
            req_headers.update(headers)

        data = None
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")

        req = urllib.request.Request(
            url=url, data=data, headers=req_headers, method=method
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_sec) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as err:
            details = ""
            try:
                details = err.read().decode("utf-8", errors="ignore")
            except Exception:
                details = ""
            raise RuntimeError(
                f"HTTP {err.code} {method} {path}: {details[:200]}"
            ) from err
        except urllib.error.URLError as err:
            raise RuntimeError(
                f"HTTP {method} {path}: {err.reason}"
            ) from err

        if not raw:
            return {}
        parsed = json.loads(raw.decode("utf-8"))
        if not isinstance(parsed, dict):
            raise RuntimeError(f"response is not a dict: {parsed!r}")
        return parsed

    def request_raw(
        self,
        method: str,
        path: str,
        data: bytes,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, bytes]:
        url = f"{self.base_url}{path}"
        req = urllib.request.Request(
            url=url, data=data, headers=headers or {}, method=method
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_sec) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as err:
            body = b""
            try:
                body = err.read()
            except Exception:
                pass
            return err.code, body
        except urllib.error.URLError as err:
            return 0, str(err.reason).encode("utf-8")


# ─── Bootstrap 认证 ─────────────────────────────────────────────────────────

class EdgeBootstrap:
    """边缘端 bootstrap 流程封装，复用 edge_server 的加密模块。"""

    def __init__(self, http: HttpClient):
        self.http = http
        self._load_keys()
        self._auth_headers: dict[str, str] | None = None

    def _load_keys(self) -> None:
        private_path = SECRET_KEY_DIR / "private.pem"
        public_path = SECRET_KEY_DIR / "public.pem"
        if not private_path.exists():
            raise FileNotFoundError(f"private key not found: {private_path}")
        if not public_path.exists():
            raise FileNotFoundError(f"public key not found: {public_path}")
        self._private_key_pem = private_path.read_bytes()
        self._public_key_pem = public_path.read_bytes()
        self._signature_algorithm = (
            CryptoUtils.detect_signature_algorithm_from_private_key(
                self._private_key_pem
            )
        )
        print(f"  [密钥] 算法={self._signature_algorithm}, 设备={DEVICE_ID}, key_id={KEY_ID}")

    def run_bootstrap(self) -> dict[str, str]:
        """执行完整 bootstrap 流程，返回认证头。"""
        # 步骤 1: 请求 challenge
        print("\n[1/3] 请求 bootstrap challenge...")
        challenge_data = self.http.request_json(
            "POST",
            "/v1/edge/auth/bootstrap/challenge",
            {
                "device_id": DEVICE_ID,
                "key_id": KEY_ID,
                "audience": "gateway",
            },
        )

        issued_at = float(challenge_data.get("issued_at_ms", 0)) / 1000.0
        expires_at = float(challenge_data.get("expires_at_ms", 0)) / 1000.0
        challenge = BootstrapChallenge(
            challenge_id=str(challenge_data.get("challenge_id", "")),
            nonce=str(challenge_data.get("nonce", "")),
            issuer=str(challenge_data.get("issuer", "")),
            audience=str(challenge_data.get("audience", "gateway")),
            issued_at=issued_at,
            expires_at=expires_at,
            entity_type=str(challenge_data.get("entity_type", "device")),
            entity_id=str(challenge_data.get("entity_id", "")),
            key_id=str(challenge_data.get("key_id", "")),
        )
        print(f"  Challenge ID: {challenge.challenge_id}")

        # 步骤 2: 构建签名并提交 proof
        print("[2/3] 签名并提交 bootstrap proof...")
        signature_payload = CryptoUtils.build_bootstrap_signature_payload(
            challenge,
            key_id=KEY_ID,
            entity_type="device",
            entity_id=DEVICE_ID,
        )
        signature = CryptoUtils.sign_by_algorithm(
            self._signature_algorithm, # type: ignore
            signature_payload,
            self._private_key_pem,
        )
        proof_payload = {
            "challenge": {
                "challenge_id": challenge.challenge_id,
                "nonce": challenge.nonce,
                "issuer": challenge.issuer,
                "audience": challenge.audience,
                "issued_at_ms": int(challenge.issued_at * 1000),
                "expires_at_ms": int(challenge.expires_at * 1000),
                "entity_type": challenge.entity_type,
                "entity_id": challenge.entity_id,
                "key_id": challenge.key_id,
            },
            "signed": {
                "challenge_id": challenge.challenge_id,
                "device_id": DEVICE_ID,
                "key_id": KEY_ID,
                "signature": signature,
                "signature_algorithm": self._signature_algorithm,
                "signed_at_ms": int(time.time() * 1000),
            },
            "scopes": [],
            "role": "device",
            "require_downstream_token": False,
        }
        auth_state = self.http.request_json(
            "POST",
            "/v1/edge/auth/bootstrap/authenticate",
            proof_payload,
        )
        stage = auth_state.get("stage", "")
        print(f"  Stage: {stage}")

        # 步骤 3: 提取 token 并构建认证头
        print("[3/3] 构建认证头...")
        tokens = auth_state.get("tokens", {})
        access_token = tokens.get("access_token", {})
        session = auth_state.get("session", {})

        access_raw = str(access_token.get("raw", ""))
        token_id = str(access_token.get("token_id", ""))
        token_type = str(access_token.get("token_type", "access"))
        session_id = str(session.get("session_id", ""))
        principal_id = str(session.get("principal_id", ""))
        scopes_list = access_token.get("scopes", [])

        headers = {
            "Authorization": f"Bearer {access_raw}",
            "x-downstream-session-id": session_id,
            "x-downstream-token-id": token_id,
            "x-token-type": token_type,
            "x-downstream-principal": principal_id,
        }
        if scopes_list:
            headers["x-scopes"] = ",".join(scopes_list)

        self._auth_headers = headers
        print(f"  会话: {session_id}")
        print(f"  Token: {token_id}")
        return headers

    @property
    def auth_headers(self) -> dict[str, str]:
        if self._auth_headers is None:
            raise RuntimeError("bootstrap not yet completed")
        return self._auth_headers


# ─── 上传请求构造器 ─────────────────────────────────────────────────────────

class EdgeUploadBuilder:
    """构建符合 data_worker EdgeEventUploadRequest 模型的 JSON payload。"""

    def __init__(self, photo_path: Path):
        self.photo_path = photo_path
        self._image_bytes = photo_path.read_bytes()
        self._class_id = _parse_class_id(photo_path.name) or "000"
        self._species = _species_name(self._class_id)
        self._image_b64 = base64.b64encode(self._image_bytes).decode("ascii")

    @property
    def image_b64(self) -> str:
        return self._image_b64

    @property
    def species(self) -> str:
        return self._species

    @property
    def class_id(self) -> str:
        return self._class_id

    def build_body(
        self,
        *,
        requires_server_assist: bool = False,
        with_local_inference: bool = False,
    ) -> dict:
        """构造上传请求体。

        Args:
            requires_server_assist: 是否需要后端辅助推理。
            with_local_inference: 是否在 payload 中包含本地推理结果。
        """
        event_id = str(uuid.uuid4())
        trace_id = str(uuid.uuid4())
        now_ms = int(time.time() * 1000)

        body: dict = {
            "event_id": event_id,
            "trace_id": trace_id,
            "requires_server_assist": requires_server_assist,
            "context": {
                "device_id": DEVICE_ID,
                "device_name": "测试设备A",
                "location_name": "测试 Location A",
                "trigger_type": "motion",
                "sensor_snapshot": {},
                "environment_snapshot": {
                    "temperature_c": 25.3,
                    "humidity_pct": 68,
                    "source": "pseudo_mock",
                    "sensor_snapshot": {},
                    "captured_at_ms": now_ms,
                },
                "captured_at_ms": now_ms,
            },
            "image": {
                "image_id": str(uuid.uuid4()),
                "format": "jpg",
                "width": 1920,
                "height": 1080,
                "checksum_sha256": _compute_sha256(self._image_bytes),
            },
            "local_inference": None,
            "metadata": {
                "test_scenario": "edge_upload_integration_test",
                "source_class_id": self._class_id,
                "source_species": self._species,
                "test_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            "image_b64": self._image_b64,
        }

        if with_local_inference:
            body["local_inference"] = self._build_local_inference()

        return body

    def _build_local_inference(self) -> dict:
        """模拟边缘端本地推理结果。

        基于图片文件名对应的真实物种构造检测+分类结果。
        """
        confidence = 0.92
        return {
            "success": True,
            "stage": "classified",
            "crop_applied": True,
            "crop_box": {"x1": 100, "y1": 150, "x2": 400, "y2": 500},
            "detector_model_version": "edge_yolo_n_v1",
            "classifier_model_version": "edge_mobilenet_cls_v1",
            "detector_model_signature": "edge_detector_sig_v1",
            "classifier_model_signature": "edge_classifier_sig_v1",
            "detection": {
                "success": True,
                "reason": None,
                "latency_ms": 45,
                "model_signature": "edge_detector_sig_v1",
                "boxes": [
                    {
                        "label": "bird",
                        "confidence": 0.95,
                        "x1": 100,
                        "y1": 150,
                        "x2": 400,
                        "y2": 500,
                    }
                ],
            },
            "classification": {
                "success": True,
                "top1_label": self._species,
                "top1_confidence": confidence,
                "latency_ms": 30,
                "reason": None,
                "model_signature": "edge_classifier_sig_v1",
                "topk": [
                    {"label": self._species, "confidence": confidence},
                    {"label": f"similar_to_{self._species}", "confidence": 0.05},
                ],
            },
            "reason": None,
        }


# ─── 测试逻辑 ───────────────────────────────────────────────────────────────

class TestRunner:
    """上传测试执行器。"""

    def __init__(self):
        self.http = HttpClient(GATEWAY_URL)
        self.bootstrap = EdgeBootstrap(self.http)
        self.photos: list[Path] = []

    def discover_photos(self) -> list[Path]:
        """从 photos 目录加载所有 jpg 图片。"""
        if not PHOTOS_DIR.exists():
            raise FileNotFoundError(f"photos dir not found: {PHOTOS_DIR}")
        photos = sorted(PHOTOS_DIR.glob("*.jpg"))
        if not photos:
            raise FileNotFoundError(f"no jpg files in {PHOTOS_DIR}")
        self.photos = photos
        print(f"\n发现 {len(photos)} 张测试图片")
        for p in photos[:5]:
            cid = _parse_class_id(p.name) or "???"
            print(f"  {p.name} -> [{cid}] {_species_name(cid)}")
        if len(photos) > 5:
            print(f"  ... 以及另外 {len(photos)-5} 张")
        return photos

    def send_upload(self, body: dict) -> tuple[int, dict]:
        """发送上传请求到网关。

        Returns:
            (status_code, parsed_response_body)
        """
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers = dict(self.bootstrap.auth_headers)
        headers["Content-Type"] = "application/json"

        status, raw = self.http.request_raw(
            "POST",
            "/v1/edge/events",
            data=data,
            headers=headers,
        )

        parsed: dict = {}
        if raw:
            try:
                parsed = json.loads(raw.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                parsed = {"_raw": raw.decode("utf-8", errors="replace")}

        return status, parsed

    def run(self) -> int:
        """运行所有测试场景。

        Returns:
            失败数（0 表示全部通过）
        """
        failures = 0
        total = 0

        # ── 阶段 1：bootstrap ──
        print("\n" + "=" * 70)
        print("阶段 1：Bootstrap 认证")
        print("=" * 70)
        try:
            self.bootstrap.run_bootstrap()
            print("\n  ✅ Bootstrap 成功")
        except Exception as e:
            print(f"\n  ❌ Bootstrap 失败: {e}")
            return 1

        # ── 阶段 2：发现图片 ──
        self.discover_photos()
        if len(self.photos) < 2:
            print("  ⚠ 至少需要 2 张图片用于测试")
            return 1

        # ── 阶段 3：场景测试 ──
        print("\n" + "=" * 70)
        print("阶段 2：上传场景测试")
        print("=" * 70)

        # ── 场景 A：边缘端已推理完成 ──
        print("\n--- 场景 A: 边缘端已推理完成 (requires_server_assist=false) ---")
        total += 1
        try:
            photo_a = self.photos[0]
            builder_a = EdgeUploadBuilder(photo_a)
            body_a = builder_a.build_body(
                requires_server_assist=False,
                with_local_inference=True,
            )
            print(f"  图片: {photo_a.name} ({builder_a.species})")
            print(f"  event_id: {body_a['event_id']}")

            status, resp = self.send_upload(body_a)
            print(f"  HTTP {status}")
            print(f"  响应: {json.dumps(resp, ensure_ascii=False, indent=2)[:300]}")

            assert status == 200, f"期望 200，实际 {status}"
            # data_worker 响应被 gateway 原样转发，所以 payload 字段就是业务响应
            # gateway 在 accepted=true 且 payload 非空时直接写 payload 到 body
            # 所以 resp 就是 data_worker 的 _build_result_payload 输出
            assert isinstance(resp, dict), f"响应应该是 dict: {type(resp)}"
            # 检查是否包含 record 信息（说明通过了 A/B 阶段）
            if "record" in resp:
                print(f"  ✅ 已存入监测记录: {resp['record'].get('id', 'N/A')}")
            elif "reason" in resp:
                print(f"  ⚠ 未存入记录，原因: {resp.get('reason', 'N/A')}")
            print("  ✅ 场景 A 通过")
        except Exception as e:
            failures += 1
            print(f"  ❌ 场景 A 失败: {e}")

        # ── 场景 B：需要后端辅助（本地未推理） ──
        print("\n--- 场景 B: 需要后端辅助 (requires_server_assist=true, 无 local_inference) ---")
        total += 1
        try:
            photo_b = self.photos[1] if len(self.photos) > 1 else self.photos[0]
            builder_b = EdgeUploadBuilder(photo_b)
            body_b = builder_b.build_body(
                requires_server_assist=True,
                with_local_inference=False,
            )
            print(f"  图片: {photo_b.name} ({builder_b.species})")
            print(f"  event_id: {body_b['event_id']}")

            status, resp = self.send_upload(body_b)
            print(f"  HTTP {status}")
            print(f"  响应: {json.dumps(resp, ensure_ascii=False, indent=2)[:300]}")

            assert status == 200, f"期望 200，实际 {status}"
            assert isinstance(resp, dict), f"响应应该是 dict: {type(resp)}"
            if "record" in resp:
                print(f"  ✅ data_worker 推理后存入监测记录")
            elif "reason" in resp:
                print(f"  ⚠ data_worker 推理后未通过置信度: {resp.get('reason', 'N/A')}")
            print("  ✅ 场景 B 通过")
        except Exception as e:
            failures += 1
            print(f"  ❌ 场景 B 失败: {e}")

        # ── 场景 C：需要后端辅助 + 无图片（测试错误处理） ──
        print("\n--- 场景 C: 需要后端辅助但无图片体 (image_b64 为空) ---")
        total += 1
        try:
            body_c = {
                "event_id": str(uuid.uuid4()),
                "trace_id": str(uuid.uuid4()),
                "requires_server_assist": True,
                "context": {
                    "device_id": DEVICE_ID,
                    "device_name": "测试设备A",
                    "location_name": "测试 Location A",
                    "trigger_type": "motion",
                    "sensor_snapshot": {},
                    "environment_snapshot": None,
                    "captured_at_ms": int(time.time() * 1000),
                },
                "image": {
                    "image_id": str(uuid.uuid4()),
                    "format": "jpg",
                    "width": 0,
                    "height": 0,
                },
                "local_inference": None,
                "metadata": {"test_scenario": "scenario_c_no_image"},
                "image_b64": "",
            }
            status, resp = self.send_upload(body_c)
            print(f"  HTTP {status}")
            print(f"  响应: {json.dumps(resp, ensure_ascii=False, indent=2)[:200]}")

            # data_worker 应该接受请求但 drop（无有效图片）
            assert status == 200, f"期望 200，实际 {status}"
            assert isinstance(resp, dict), f"响应应该是 dict"
            print("  ✅ 场景 C 通过（空图片被正确处理）")
        except Exception as e:
            failures += 1
            print(f"  ❌ 场景 C 失败: {e}")

        # ── 汇总 ──
        print("\n" + "=" * 70)
        print(f"测试完成: {total - failures}/{total} 通过, {failures} 失败")
        print("=" * 70)
        return failures


def main() -> int:
    print("=" * 70)
    print("边缘端上传接口集成测试")
    print(f"网关: {GATEWAY_URL}")
    print(f"设备: {DEVICE_ID}")
    print(f"密钥: {KEY_ID}")
    print("=" * 70)

    runner = TestRunner()
    return runner.run()


if __name__ == "__main__":
    exit(main())
