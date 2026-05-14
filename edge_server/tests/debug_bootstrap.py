#!/usr/bin/env python3
"""直接调试bootstrap流程"""
import sys
sys.path.insert(0, '.')
import json
import urllib.request
import time
from src.utils.crypto_utils import CryptoUtils
from src.models.auth.bootstrap import BootstrapChallenge

gateway_url = 'http://127.0.0.1:8080'
device_id = '6a9d6b92-fe06-44ee-a607-7284e783f738'
key_id = '626efa4f-0cd0-4e81-af6e-447b41bac8fc'

# 步骤1：获取challenge
print('[1] 请求bootstrap challenge...')
payload = {
    'device_id': device_id,
    'key_id': key_id,
    'audience': 'gateway',
}

url = f'{gateway_url}/v1/edge/auth/bootstrap/challenge'
headers = {'Content-Type': 'application/json'}
data = json.dumps(payload, ensure_ascii=False).encode('utf-8')

req = urllib.request.Request(url=url, data=data, headers=headers, method='POST')
with urllib.request.urlopen(req, timeout=5.0) as resp:
    raw = resp.read()
    challenge_response = json.loads(raw.decode('utf-8'))
    print(f'Challenge ID: {challenge_response.get("challenge_id")}')
    
    # 转换时间戳
    issued_at = float(challenge_response.get('issued_at_ms', 0)) / 1000.0
    expires_at = float(challenge_response.get('expires_at_ms', 0)) / 1000.0
    
    challenge = BootstrapChallenge(
        challenge_id=str(challenge_response.get('challenge_id')),
        nonce=str(challenge_response.get('nonce')),
        issuer=str(challenge_response.get('issuer')),
        audience=str(challenge_response.get('audience')),
        issued_at=issued_at,
        expires_at=expires_at,
        entity_type=str(challenge_response.get('entity_type')),
        entity_id=str(challenge_response.get('entity_id')),
        key_id=str(challenge_response.get('key_id')),
    )

print(f'Challenge object: {challenge}')
print(f'Challenge ID value: "{challenge.challenge_id}"')
print(f'Challenge ID type: {type(challenge.challenge_id)}')

# 步骤2：构建proof
print('[2] 构建bootstrap proof...')
private_key_pem = open('secret_keys/private.pem', 'rb').read()

signature_algorithm = CryptoUtils.detect_signature_algorithm_from_private_key(private_key_pem)
print(f'Signature algorithm: {signature_algorithm}')

signature_payload = CryptoUtils.build_bootstrap_signature_payload(
    challenge,
    key_id=key_id,
    entity_type='device',
    entity_id=device_id,
)

print(f'Signature payload (first 100 chars): {signature_payload[:100]}')

signature = CryptoUtils.sign_by_algorithm(
    signature_algorithm,
    signature_payload,
    private_key_pem,
)

# 发送proof
print('[3] 提交bootstrap proof...')
proof_payload = {
    'challenge': {
        'challenge_id': challenge.challenge_id,
        'nonce': challenge.nonce,
        'issuer': challenge.issuer,
        'audience': challenge.audience,
        'issued_at_ms': int(round(challenge.issued_at * 1000.0)),
        'expires_at_ms': int(round(challenge.expires_at * 1000.0)),
        'entity_type': challenge.entity_type,
        'entity_id': challenge.entity_id,
        'key_id': challenge.key_id,
    },
    'signed': {
        'challenge_id': challenge.challenge_id,
        'device_id': device_id,
        'key_id': key_id,
        'signature': signature,
        'signature_algorithm': signature_algorithm,
        'signed_at_ms': int(time.time() * 1000),
    },
    'scopes': [],
    'role': 'device',
    'require_downstream_token': False,
}

print(f'Proof payload keys: {list(proof_payload.keys())}')
print(f'Challenge in payload: {proof_payload["challenge"]["challenge_id"]}')
print(f'Signed in payload: {proof_payload["signed"]["challenge_id"]}')

url_auth = f'{gateway_url}/v1/edge/auth/bootstrap/authenticate'
data_auth = json.dumps(proof_payload, ensure_ascii=False).encode('utf-8')
req_auth = urllib.request.Request(url=url_auth, data=data_auth, headers=headers, method='POST')

try:
    with urllib.request.urlopen(req_auth, timeout=5.0) as resp:
        raw = resp.read()
        auth_response = json.loads(raw.decode('utf-8'))
        print(f'[OK] Auth successful: {auth_response.get("stage")}')
        print('Token Info:')
        tokens = auth_response.get('tokens', {})
        if tokens.get('access_token'):
            print(f'  - Access Token ID: {tokens["access_token"].get("token_id")}')
        if tokens.get('refresh_token'):
            print(f'  - Refresh Token ID: {tokens["refresh_token"].get("token_id")}')
except urllib.error.HTTPError as e: # type: ignore
    error_body = e.read().decode('utf-8')
    print(f'[ERROR] HTTP {e.code}: {error_body}')
    import traceback
    traceback.print_exc()
