"""转发认证与下游上下文请求头键。

这些常量用于在拦截器、用例层和出站代码之间保持键名稳定。
"""

HEADER_AUTH_VERIFIED = "x-auth-verified"
HEADER_TRUE = "1"

HEADER_VERIFIED_PRINCIPAL_ID = "x-verified-principal-id"
HEADER_VERIFIED_SESSION_ID = "x-verified-session-id"
HEADER_VERIFIED_TOKEN_ID = "x-verified-token-id"
HEADER_VERIFIED_GATEWAY_ID = "x-verified-gateway-id"
HEADER_VERIFIED_SOURCE_SERVICE = "x-verified-source-service"
HEADER_VERIFIED_TARGET_SERVICE = "x-verified-target-service"
HEADER_VERIFIED_ENTITY_TYPE = "x-verified-entity-type"
HEADER_VERIFIED_ENTITY_ID = "x-verified-entity-id"
HEADER_VERIFIED_SCOPES = "x-verified-scopes"
HEADER_VERIFIED_TRACE_ID = "x-verified-trace-id"
HEADER_VERIFIED_REQUEST_ID = "x-verified-request-id"

HEADER_DOWNSTREAM_PRINCIPAL = "x-downstream-principal"
HEADER_DOWNSTREAM_SESSION_ID = "x-downstream-session-id"
HEADER_DOWNSTREAM_TOKEN_ID = "x-downstream-token-id"
HEADER_DOWNSTREAM_SOURCE_SERVICE = "x-downstream-source-service"
HEADER_DOWNSTREAM_TARGET_SERVICE = "x-downstream-target-service"
HEADER_DOWNSTREAM_GRANT_ISSUED_AT = "x-downstream-grant-issued-at"
HEADER_DOWNSTREAM_GRANT_EXPIRES_AT = "x-downstream-grant-expires-at"
HEADER_DOWNSTREAM_AUTH_VERIFY_MODE = "x-downstream-auth-verify-mode"
DOWNSTREAM_AUTH_VERIFY_MODE_AUTHORITY_DOUBLE_CHECK = "authority-double-check"

HEADER_GATEWAY_ID = "x-gateway-id"
HEADER_SOURCE_SERVICE = "x-source-service"
HEADER_TARGET_SERVICE = "x-target-service"
HEADER_SCOPES = "x-scopes"
HEADER_TRACE_ID = "x-trace-id"
HEADER_REQUEST_ID = "x-request-id"

HEADER_MODULE = "x-module"
HEADER_ACTION = "x-action"
HEADER_FORWARDED_FOR = "x-forwarded-for"
HEADER_REAL_IP = "x-real-ip"
HEADER_CLIENT_ID = "x-client-id"
HEADER_TOKEN_TYPE = "x-token-type"
