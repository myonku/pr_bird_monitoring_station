# Edge Auth Design Spec

## 1. Goal

This document defines edge-side authentication architecture for the bird monitoring platform.

Scope:
- Edge device authentication and token lifecycle.
- Session and credential management for HTTP business requests to gateway.
- Separation of authentication flow from business upload/inference flow.

Out of scope:
- Business payload schema and upload orchestration details.
- Database schema changes on edge side.
- Transport-level encryption between edge and gateway.


## 2. Constraints and Assumptions

1. Edge runtime cannot connect remote databases.
2. Edge only uses local trust material as initial credential:
- private key from local storage, TPM, secure element, or file-based keystore.
- matching public key is pre-registered in system database.
3. Edge to gateway communication is business HTTP only.
4. No additional app-layer encryption is required between edge and gateway.
5. Auth center is not called directly by edge:
- edge calls gateway auth endpoints.
- gateway forwards auth calls to auth center.
6. Edge still follows session + short/long token model:
- access token for request auth.
- refresh token for renewal.
- session for lifecycle and revocation tracking.


## 3. Layering and Isolation

Authentication must be independent from business features (capture/inference/upload).

Boundary:
- Business modules only depend on an auth header provider abstraction.
- Business modules do not build bootstrap requests, sign challenges, or refresh tokens.
- Business modules do not parse auth responses.

Recommended dependency direction:
- business pipeline -> IEdgeAuthCoordinator
- IEdgeAuthCoordinator -> ISecretKeyProvider, IEdgeGatewayAuthClient, IEdgeAuthStateStore
- auth components must not depend on business pipeline modules


## 4. Interface Set

Implemented in:
- src/auth_interface.py
- src/models/auth_models.py
- src/utils/crypto_utils.py
- src/utils/secret_key_utils.py

Core abstractions:
1. ISecretKeyProvider
- Provides local trust material, key lookup, private key loading, and bootstrap challenge signing.

2. IEdgeGatewayAuthClient
- Calls gateway auth APIs:
- init bootstrap challenge
- authenticate bootstrap
- refresh token
- verify token
- revoke token/family

3. IEdgeAuthStateStore
- Persists auth state locally (session + token bundle + stage).
- Suggested storage options: file, sqlite, lightweight kv.

4. IEdgeAuthCoordinator
- Auth orchestration entry for business modules.
- Exposes:
- ensure_ready
- get_auth_headers
- on_unauthorized
- logout


## 5. Data Contracts

Key contracts are in src/models/auth_models.py:
- LocalTrustMaterial
- BootstrapChallenge
- SignedBootstrapProof
- EdgeToken / EdgeTokenBundle
- EdgeSession
- EdgeAuthState
- RefreshTokenRequest
- TokenVerificationResult
- EdgeAuthHeaders

Design note:
- Keep model fields protocol-neutral where possible.
- Map to concrete gateway HTTP payloads in adapter/client layer.

### 5.1 Bootstrap Signature Payload Canonical Format

Edge signer must build payload exactly as auth center verifier expects:

- challenge_id|issuer|audience|entity_type|entity_id|key_id|nonce|issued_at_rfc3339nano|expires_at_rfc3339nano

This is implemented in src/utils/crypto_utils.py by:
- CryptoUtils.build_bootstrap_signature_payload
- CryptoUtils.unix_ts_to_rfc3339nano

Key loading and local key catalog lookup are implemented in src/utils/secret_key_utils.py by:
- SecretKeyUtils.load_pem_bytes_from_ref
- SecretKeyUtils.get_public_key_by_key_id
- SecretKeyUtils.get_private_key_pem
- SecretKeyUtils.sign_bootstrap_challenge

Supported signature algorithms:
- ed25519
- ecdsa_p256_sha256
- rsa_pss_sha256


## 6. End-to-End Flow

### Phase A: Cold Start Bootstrap

1. Edge starts and calls IEdgeAuthCoordinator.ensure_ready().
2. Coordinator loads local state from IEdgeAuthStateStore.
3. If no valid session/token:
- select key material via ISecretKeyProvider
- request challenge via IEdgeGatewayAuthClient.init_bootstrap_challenge()
- sign challenge via ISecretKeyProvider.sign_bootstrap_challenge()
- submit proof via IEdgeGatewayAuthClient.authenticate_bootstrap()
4. Persist resulting EdgeAuthState to IEdgeAuthStateStore.
5. System enters ready state.

### Phase B: Business Request Authorization

1. Business uploader asks IEdgeAuthCoordinator.get_auth_headers().
2. Coordinator ensures access token is valid:
- if expiring/expired, refresh via IEdgeGatewayAuthClient.refresh_tokens()
3. Coordinator returns EdgeAuthHeaders for HTTP request.
4. Uploader adds these headers and sends business payload.

### Phase C: Unauthorized Recovery

1. Business request gets 401/403 from gateway.
2. Uploader reports this via IEdgeAuthCoordinator.on_unauthorized().
3. Coordinator strategy:
- first try refresh token flow;
- if refresh failed, clear local state and re-bootstrap.
4. Save updated state and continue retry policy.

### Phase D: Logout or Key Rotation

1. On explicit logout or key rotation event:
- call IEdgeGatewayAuthClient.revoke()
- clear local state via IEdgeAuthStateStore.clear()
2. Next ensure_ready() starts new bootstrap with latest local key material.


## 7. Gateway API Expectations (Forwarded to Auth Center)

Edge-facing (gateway hosted) API set should include:
- POST /v1/edge/auth/bootstrap/challenge
- POST /v1/edge/auth/bootstrap/authenticate
- POST /v1/edge/auth/token/refresh
- POST /v1/edge/auth/token/verify
- POST /v1/edge/auth/token/revoke

Gateway responsibilities:
- authenticate and validate edge request envelope.
- forward to auth center.
- map auth center response to edge contract.


## 8. Operational Guidance

1. Local state durability
- Persist refresh token and session atomically.
- Prevent partial writes that leave unusable mixed states.

2. Time handling
- Use monotonic-safe strategy for token expiry checks when possible.
- Keep gateway and edge clock skew allowance configurable.

3. Retry and backoff
- Backoff bootstrap/refresh calls to avoid gateway storm during unstable networks.

4. Key protection
- private_key_ref should point to protected key source.
- avoid exporting raw private key in logs, memory dumps, or telemetry.

5. Audit fields
- always include request_id and trace_id on refresh/verify calls.


## 9. Integration Plan (Non-breaking)

Step 1:
- Introduce auth interfaces and models (this change).

Step 2:
- Implement IEdgeGatewayAuthClient over existing HTTP transport primitives.

Step 3:
- Add concrete IEdgeAuthCoordinator + local store implementation.

Step 4:
- Update uploader transport path to request headers from IEdgeAuthCoordinator instead of static auth_token config.

Step 5:
- Keep old static auth_token as fallback for migration window, then remove.
