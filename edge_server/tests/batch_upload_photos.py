"""
批量上传剩余测试图片到 data_worker。
已上传的 001、002 自动跳过。
"""
import base64
import hashlib
import json
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

EDGE_SERVER_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(EDGE_SERVER_ROOT))

import urllib.request
import urllib.error
from src.utils.crypto_utils import CryptoUtils
from src.models.auth.bootstrap import BootstrapChallenge

GATEWAY_URL = "http://127.0.0.1:8080"
SKIP_CLASS_IDS = {"001", "002"}

PHOTO_DIR = EDGE_SERVER_ROOT / "tests" / "photos"
LABEL_FILE = EDGE_SERVER_ROOT / "model_pack" / "labels.txt"
SITE_A_PRIVATE_KEY_FILE = EDGE_SERVER_ROOT / "secret_keys" / "private.pem"

# 用于临时切换上传源的相关信息
EDGE_SERVER_B_ID = "e488be34-8672-4afb-bdb0-f8dc6af0cbc8"
EDGE_SERVER_B_KEY_ID = "b147919c-1f97-46a4-9405-baf91b280f45"
EDGE_SERVER_B_NAME = "测试站点 B"
EDGE_SERVER_B_LOCATION = "Location B"
EDGE_SERVER_B_KEY_PAIR = {
    "private_key": """-----BEGIN PRIVATE KEY-----
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
eBAWJqNdGCbQ9ewJx5XWthP+yKf1
-----END PRIVATE KEY-----
""",
    "public_key": """-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlVBXqs7dL4CwrmrukKxg
B7iO+A7ZR70BM0Un62Yco4Q+eZlTCB5fwuljH4JOychALxD35lMrrPxw5zmVUMn2
yLG/uViQOGLFJlsaQ622F2njUCtsLFF7cPKSjR3yVTrTqQLRbyyj9tmKYxgtWcBw
Zcm3BZB1cAFPKP6kjHodnOxH5J0B2LwmamCy6Qc0VmofBwjw/iKRsJLMBorO7Vah
gw3WnVUkFs5icxeDUJDRN56KAxJnzqovjrCucAyP5KouDQ43rYNH/20Kl+H3Hmlo
Ga+4VtuRW9fM2PHbjS1tP5cxpzpZ1dP1raOr8s1FKl1kKBIgxvI+PFh47GP+xLVM
2xbKsdnMK82GWiWI5+zu4ZmZ82Z1ozwalbFAFaY34Id7PQxxSXkAyiBJJN+iq0Ha
28ZKX3NHrbHtB4meWp2owjDTsYunmPzlAcwgP/pw0TucGWxn7Un4+WI/YJwSZveR
yHoyL1wdXSlIeP6wUmsyB38mhxfLm278d9KBGg5edh4le7d0xIkL9vRCq30QjysA
x4COm4QAqRve+QfLuGNh3xtBPfncWJZcc+IvV95OCcDTKF0Pvotf/8/uIChbhT0i
oRc5UgZQEVibK0Yxfyy7CuN/KDdYY21mzfW2CLsTNRmo5BRt4FjhgpQgBfBmmwoE
yf7pCZVrWte9DoudPKucScsCAwEAAQ==
-----END PUBLIC KEY-----""",
}


@dataclass(slots=True)
class SiteSource:
    name: str
    device_id: str
    key_id: str
    device_name: str
    location_name: str
    private_key_pem: bytes


SITE_SOURCES = (
    SiteSource(
        name="A",
        device_id="6a9d6b92-fe06-44ee-a607-7284e783f738",
        key_id="626efa4f-0cd0-4e81-af6e-447b41bac8fc",
        device_name="测试设备A",
        location_name="测试 Location A",
        private_key_pem=b"",
    ),
    SiteSource(
        name="B",
        device_id=EDGE_SERVER_B_ID,
        key_id=EDGE_SERVER_B_KEY_ID,
        device_name=EDGE_SERVER_B_NAME,
        location_name=EDGE_SERVER_B_LOCATION,
        private_key_pem=b"",
    ),
)


def bootstrap(site: SiteSource) -> dict[str, str]:
    """执行 bootstrap 并返回认证头。"""
    priv = site.private_key_pem or SITE_A_PRIVATE_KEY_FILE.read_bytes()
    alg = CryptoUtils.detect_signature_algorithm_from_private_key(priv)

    def _req(method, path, payload=None, headers=None):
        url = f"{GATEWAY_URL}{path}"
        data = json.dumps(payload).encode() if payload else None
        req = urllib.request.Request(
            url, data=data, headers=headers or {"Content-Type": "application/json"}, method=method
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())

    # challenge
    cd = _req("POST", "/v1/edge/auth/bootstrap/challenge",
              {"device_id": site.device_id, "key_id": site.key_id, "audience": "gateway"})
    ch = BootstrapChallenge(
        challenge_id=str(cd["challenge_id"]), nonce=str(cd["nonce"]),
        issuer=str(cd["issuer"]), audience=str(cd.get("audience", "gateway")),
        issued_at=float(cd["issued_at_ms"]) / 1000,
        expires_at=float(cd["expires_at_ms"]) / 1000,
        entity_type=str(cd.get("entity_type", "device")),
        entity_id=str(cd.get("entity_id", "")),
        key_id=str(cd.get("key_id", "")),
    )
    # proof
    sig_payload = CryptoUtils.build_bootstrap_signature_payload(
        ch, key_id=site.key_id, entity_type="device", entity_id=site.device_id
    )
    sig = CryptoUtils.sign_by_algorithm(alg, sig_payload, priv)
    st = _req("POST", "/v1/edge/auth/bootstrap/authenticate", {
        "challenge": {
            "challenge_id": ch.challenge_id, "nonce": ch.nonce,
            "issuer": ch.issuer, "audience": ch.audience,
            "issued_at_ms": int(ch.issued_at * 1000),
            "expires_at_ms": int(ch.expires_at * 1000),
            "entity_type": ch.entity_type, "entity_id": ch.entity_id,
            "key_id": ch.key_id,
        },
        "signed": {
            "challenge_id": ch.challenge_id, "device_id": site.device_id,
            "key_id": site.key_id, "signature": sig,
            "signature_algorithm": alg,
            "signed_at_ms": int(time.time() * 1000),
        },
        "scopes": [], "role": "device", "require_downstream_token": False,
    })
    ac = st["tokens"]["access_token"]
    ss = st["session"]
    return {
        "Authorization": f"Bearer {ac['raw']}",
        "x-downstream-session-id": ss["session_id"],
        "x-downstream-token-id": ac["token_id"],
        "x-token-type": ac["token_type"],
        "x-downstream-principal": ss["principal_id"],
        "Content-Type": "application/json",
    }


def load_labels() -> dict[str, str]:
    labels = {}
    path = LABEL_FILE
    if not path.exists():
        return labels
    for line in path.read_text().strip().splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            labels[parts[0]] = parts[1]
    return labels


def upload_photo(
    headers: dict,
    photo_path: Path,
    species: str,
    *,
    site: SiteSource,
    is_edge_processed: bool,
):
    """上传单张图片。"""
    img = photo_path.read_bytes()
    now_ms = int(time.time() * 1000)
    body = {
        "event_id": str(uuid.uuid4()),
        "trace_id": str(uuid.uuid4()),
        "requires_server_assist": not is_edge_processed,
        "context": {
            "device_id": site.device_id,
            "device_name": site.device_name,
            "location_name": site.location_name,
            "trigger_type": "motion",
            "sensor_snapshot": {},
            "environment_snapshot": {
                "temperature_c": 25.3, "humidity_pct": 68,
                "source": "pseudo_mock", "sensor_snapshot": {},
                "captured_at_ms": now_ms,
            },
            "captured_at_ms": now_ms,
        },
        "image": {
            "image_id": str(uuid.uuid4()), "format": "jpg",
            "width": 1920, "height": 1080,
            "checksum_sha256": hashlib.sha256(img).hexdigest(),
        },
        "local_inference": None,
        "metadata": {
            "test_scenario": "batch_upload",
            "source_class_id": photo_path.name.split("-")[0],
            "source_species": species,
            "source_station": site.name,
            "source_device_id": site.device_id,
        },
        "image_b64": base64.b64encode(img).decode(),
    }

    if is_edge_processed:
        body["local_inference"] = {
            "success": True,
            "stage": "classified",
            "crop_applied": True,
            "crop_box": {"x1": 100, "y1": 150, "x2": 400, "y2": 500},
            "detector_model_version": "edge_yolo_n_v1",
            "classifier_model_version": "edge_mobilenet_cls_v1",
            "detector_model_signature": "sig_v1",
            "classifier_model_signature": "sig_v1",
            "detection": {
                "success": True, "reason": None, "latency_ms": 45,
                "model_signature": "sig_v1",
                "boxes": [{"label": "bird", "confidence": 0.95,
                           "x1": 100, "y1": 150, "x2": 400, "y2": 500}],
            },
            "classification": {
                "success": True, "top1_label": species,
                "top1_confidence": 0.92, "latency_ms": 30,
                "reason": None, "model_signature": "sig_v1",
                "topk": [
                    {"label": species, "confidence": 0.92},
                    {"label": "similar", "confidence": 0.05},
                ],
            },
            "reason": None,
        }

    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        f"{GATEWAY_URL}/v1/edge/events",
        data=data, headers=headers, method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.status, json.loads(resp.read())


def main():
    print("=" * 60)
    print("批量上传测试图片")
    print("=" * 60)

    # Bootstrap
    site_headers: dict[str, dict[str, str]] = {}
    print("\n[1] Bootstrap 认证...")
    for site in SITE_SOURCES:
        print(f"  - 站点 {site.name} 认证中...")
        site_headers[site.name] = bootstrap(site)
        print(f"    站点 {site.name} OK")

    # 标签
    labels = load_labels()
    print(f"  加载 {len(labels)} 个物种标签")

    # 收集图片
    photos = sorted(PHOTO_DIR.glob("*.jpg"))
    to_upload = [p for p in photos if p.name.split("-")[0] not in SKIP_CLASS_IDS]
    print(f"\n[2] 待上传: {len(to_upload)} 张 (已跳过 {len(photos) - len(to_upload)} 张)")

    site_groups = {
        SITE_SOURCES[0].name: to_upload[::2],
        SITE_SOURCES[1].name: to_upload[1::2],
    }
    for site in SITE_SOURCES:
        group = site_groups[site.name]
        edge_count = sum(1 for i in range(len(group)) if i % 2 == 0)
        server_count = len(group) - edge_count
        print(f"  站点 {site.name}: {len(group)} 张 (边缘已处理 {edge_count} / 后端辅助 {server_count})")

    # 上传
    ok = fail = 0
    for site in SITE_SOURCES:
        site_photos = site_groups[site.name]
        headers = site_headers[site.name]
        print(f"\n[3] 开始上传站点 {site.name} 的 {len(site_photos)} 张图片...")
        for i, ph in enumerate(site_photos):
            cid = ph.name.split("-")[0]
            species = labels.get(cid, f"unknown_{cid}")
            is_edge = (i % 2 == 0)
            label = "边缘处理" if is_edge else "后端辅助"
            try:
                status, _ = upload_photo(
                    headers,
                    ph,
                    species,
                    site=site,
                    is_edge_processed=is_edge,
                )
                if status == 200:
                    print(f"  [{site.name}] [{ph.name}] {species:30s} {label}  OK")
                    ok += 1
                else:
                    print(f"  [{site.name}] [{ph.name}] {species:30s} {label}  HTTP {status}")
                    fail += 1
            except Exception as e:
                print(f"  [{site.name}] [{ph.name}] {species:30s} {label}  FAIL {e}")
                fail += 1

    # 汇总
    print(f"\n{'=' * 60}")
    print(f"结果: {ok} 成功 / {fail} 失败 / 共 {ok + fail} 张")
    print(f"{'=' * 60}")
    return fail


if __name__ == "__main__":
    exit(main())
