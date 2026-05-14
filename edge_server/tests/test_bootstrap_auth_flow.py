"""
模拟edge_server的bootstrap和token刷新认证流程测试。

此测试伪造edge_server的请求，通过网关转发到认证中心进行验证。
测试流程：
1. 请求bootstrap challenge
2. 使用edge_server的私钥签名challenge
3. 提交bootstrap proof
4. 使用refresh token进行刷新
"""
import json
import sys
import time
import uuid
from pathlib import Path

# 添加edge_server到路径，以便导入其代码
EDGE_SERVER_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(EDGE_SERVER_ROOT))

from src.utils.crypto_utils import CryptoUtils
from src.models.auth.bootstrap import BootstrapChallenge, SignedBootstrapProof
from src.models.auth.auth import SignatureAlgorithm
import urllib.request
import urllib.error


class EdgeBootstrapAuthTester:
    """边缘端认证流程测试器。"""

    def __init__(self, gateway_url: str, edge_config: dict, device_id: str, key_id: str):
        """
        初始化测试器。
        
        Args:
            gateway_url: 网关地址（如 http://127.0.0.1:8080）
            edge_config: edge_server的配置字典
            device_id: 设备ID
            key_id: 密钥ID
        """
        self.gateway_url = gateway_url.rstrip("/")
        self.edge_config = edge_config
        self.device_id = device_id
        self.key_id = key_id
        
        # 读取edge_server的密钥
        secret_key_dir = Path(edge_config.get("auth", {}).get("secret_key_dir", "secret_keys"))
        if not secret_key_dir.is_absolute():
            secret_key_dir = EDGE_SERVER_ROOT / secret_key_dir
        
        private_key_path = secret_key_dir / "private.pem"
        public_key_path = secret_key_dir / "public.pem"
        
        if not private_key_path.exists():
            raise FileNotFoundError(f"Private key not found: {private_key_path}")
        if not public_key_path.exists():
            raise FileNotFoundError(f"Public key not found: {public_key_path}")
        
        self.private_key_pem = private_key_path.read_bytes()
        self.public_key_pem = public_key_path.read_bytes()
        
        # 检测签名算法
        self.signature_algorithm = CryptoUtils.detect_signature_algorithm_from_private_key(
            self.private_key_pem
        )
        
        print(f"[OK] 密钥加载成功")
        print(f"  - 签名算法: {self.signature_algorithm}")
        print(f"  - 设备ID: {self.device_id}")
        print(f"  - 密钥ID: {self.key_id}")

    def _request_json(
        self,
        method: str,
        path: str,
        payload: dict | None = None,
    ) -> dict:
        """发送HTTP请求到网关。"""
        url = f"{self.gateway_url}{path}"
        headers = {"Content-Type": "application/json"}
        data = None
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")

        req = urllib.request.Request(url=url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as err:
            details = ""
            try:
                details = err.read().decode("utf-8", errors="ignore")
            except Exception:
                details = ""
            raise RuntimeError(
                f"Gateway request failed: method={method} path={path} "
                f"status={err.code} body={details}"
            ) from err
        except urllib.error.URLError as err:
            raise RuntimeError(
                f"Gateway request failed: method={method} path={path} reason={err.reason}"
            ) from err

        if not raw:
            return {}
        parsed = json.loads(raw.decode("utf-8"))
        if not isinstance(parsed, dict):
            raise RuntimeError(
                f"Gateway response is not an object: method={method} path={path}"
            )
        return parsed

    def request_bootstrap_challenge(self) -> BootstrapChallenge:
        """请求bootstrap challenge。"""
        print("\n[1] 请求bootstrap challenge...")
        payload = {
            "device_id": self.device_id,
            "key_id": self.key_id,
            "audience": "gateway",
        }
        data = self._request_json(
            "POST",
            "/v1/edge/auth/bootstrap/challenge",
            payload,
        )
        
        # 提取UUID，可能返回为dict格式
        challenge_id_raw = data.get("challenge_id", "")
        if isinstance(challenge_id_raw, dict):
            challenge_id_str = str(challenge_id_raw)
        else:
            challenge_id_str = str(challenge_id_raw)
        
        # 处理时间戳：网关返回毫秒时间戳（issued_at_ms/expires_at_ms）
        # 转换为秒时间戳（float）供edge_server处理
        issued_at_ms = data.get("issued_at_ms", data.get("issued_at", 0))
        expires_at_ms = data.get("expires_at_ms", data.get("expires_at", 0))
        issued_at = float(issued_at_ms) / 1000.0 if issued_at_ms else 0.0
        expires_at = float(expires_at_ms) / 1000.0 if expires_at_ms else 0.0
        
        challenge = BootstrapChallenge(
            challenge_id=challenge_id_str,
            nonce=str(data.get("nonce", "")),
            issuer=str(data.get("issuer", "")),
            audience=str(data.get("audience", "gateway")),
            issued_at=issued_at,
            expires_at=expires_at,
            entity_type=str(data.get("entity_type", "device")),
            entity_id=str(data.get("entity_id", "")),
            key_id=str(data.get("key_id", "")),
        )
        print(f"[OK] Challenge 获取成功")
        print(f"  - Challenge ID: {challenge.challenge_id}")
        print(f"  - Nonce: {challenge.nonce}")
        print(f"  - Issued At: {challenge.issued_at}")
        print(f"  - Expires At: {challenge.expires_at}")
        return challenge

    def submit_bootstrap_proof(
        self,
        challenge: BootstrapChallenge,
    ) -> dict:
        """提交bootstrap proof。"""
        print("\n[2] 构建并提交bootstrap proof...")
        
        # 构建签名payload
        signature_payload = CryptoUtils.build_bootstrap_signature_payload(
            challenge,
            key_id=self.key_id,
            entity_type="device",
            entity_id=self.device_id,
        )
        
        print(f"  - 签名载荷: {signature_payload[:100]}...")
        
        # 签名
        signature = CryptoUtils.sign_by_algorithm(
            self.signature_algorithm, # type: ignore
            signature_payload,
            self.private_key_pem,
        )
        
        print(f"  - 签名: {signature[:50]}...")
        
        # 网关期望的请求格式包含challenge和signed两个部分
        proof_payload = {
            "challenge": {
                "challenge_id": challenge.challenge_id,
                "nonce": challenge.nonce,
                "issuer": challenge.issuer,
                "audience": challenge.audience,
                "issued_at_ms": int(round(challenge.issued_at * 1000.0)),
                "expires_at_ms": int(round(challenge.expires_at * 1000.0)),
                "entity_type": challenge.entity_type,
                "entity_id": challenge.entity_id,
                "key_id": challenge.key_id,
            },
            "signed": {
                "challenge_id": challenge.challenge_id,
                "device_id": self.device_id,
                "key_id": self.key_id,
                "signature": signature,
                "signature_algorithm": self.signature_algorithm,
                "signed_at_ms": int(time.time() * 1000),
            },
            "scopes": [],
            "role": "device",
            "require_downstream_token": False,
        }
        
        print(f"  - 请求payload已构建 (challenge + signed)")
        
        data = self._request_json(
            "POST",
            "/v1/edge/auth/bootstrap/authenticate",
            proof_payload,
        )
        
        print(f"[OK] Bootstrap 认证成功")
        print(f"  - 阶段: {data.get('stage', 'unknown')}")
        
        # 提取token信息
        tokens = data.get("tokens", {})
        if tokens:
            access_token = tokens.get("access_token", {})
            refresh_token = tokens.get("refresh_token", {})
            print(f"  - Access Token ID: {access_token.get('token_id', 'N/A')}")
            print(f"  - Refresh Token ID: {refresh_token.get('token_id', 'N/A')}")
            print(f"  - 会话ID: {data.get('session', {}).get('session_id', 'N/A')}")
        
        return data

    def refresh_tokens(self, auth_state: dict) -> dict:
        """刷新tokens。"""
        print("\n[3] 刷新tokens...")
        
        tokens = auth_state.get("tokens", {})
        refresh_token = tokens.get("refresh_token", {})
        
        if not refresh_token:
            print("[FAIL] 无可用的refresh token，跳过刷新")
            return {}
        
        refresh_token_raw = refresh_token.get("raw", "")
        if not refresh_token_raw:
            print("[FAIL] Refresh token为空，跳过刷新")
            return {}
        
        payload = {
            "refresh_token": refresh_token_raw,
            "client_id": "edge-server-test",
            "gateway_id": "gateway",
            "source_ip": "127.0.0.1",
            "user_agent": "edge-server-test",
            "request_id": str(uuid.uuid4()),
            "trace_id": str(uuid.uuid4()),
        }
        
        data = self._request_json(
            "POST",
            "/v1/edge/auth/token/refresh",
            payload,
        )
        
        print(f"[OK] Token 刷新成功")
        
        # 提取新的token信息
        tokens = data.get("tokens", {})
        if tokens:
            access_token = tokens.get("access_token", {})
            refresh_token_new = tokens.get("refresh_token", {})
            print(f"  - 新 Access Token ID: {access_token.get('token_id', 'N/A')}")
            print(f"  - 新 Refresh Token ID: {refresh_token_new.get('token_id', 'N/A')}")
        
        return data

    def run_full_flow(self) -> bool:
        """运行完整的认证流程。"""
        print("=" * 70)
        print("边缘端认证流程测试")
        print("=" * 70)
        
        try:
            # 步骤1：请求challenge
            challenge = self.request_bootstrap_challenge()
            
            # 步骤2：提交proof
            auth_state = self.submit_bootstrap_proof(challenge)
            
            # 步骤3：刷新tokens
            refreshed_state = self.refresh_tokens(auth_state)
            
            print("\n" + "=" * 70)
            print("[OK] 认证流程完成！")
            print("=" * 70)
            return True
        except Exception as e:
            print(f"\n[FAIL] 认证流程失败: {e}")
            import traceback
            traceback.print_exc()
            return False


def load_edge_config() -> dict:
    """加载edge_server的配置。"""
    config_path = EDGE_SERVER_ROOT / "settings.toml"
    if not config_path.exists():
        raise FileNotFoundError(f"Edge config not found: {config_path}")
    
    # 简单的TOML解析（只支持我们需要的部分）
    import tomllib
    
    with open(config_path, "rb") as f:
        config = tomllib.load(f)
    
    return config


if __name__ == "__main__":
    try:
        # 加载配置
        edge_config = load_edge_config()
        
        # 从设置中读取device_id和key_id
        device_id = edge_config.get("runtime", {}).get("device_id", "unknown")
        active_key_id = edge_config.get("auth", {}).get("active_key_id", "unknown")
        gateway_url = edge_config.get("upload_http", {}).get("base_backend_url", "http://127.0.0.1:8080")
        
        print(f"配置加载成功")
        print(f"  - 设备ID: {device_id}")
        print(f"  - 活跃密钥ID: {active_key_id}")
        print(f"  - 网关URL: {gateway_url}")
        
        # 创建测试器
        tester = EdgeBootstrapAuthTester(
            gateway_url=gateway_url,
            edge_config=edge_config,
            device_id=device_id,
            key_id=active_key_id,
        )
        
        # 运行认证流程
        success = tester.run_full_flow()
        sys.exit(0 if success else 1)
        
    except Exception as e:
        print(f"初始化失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
