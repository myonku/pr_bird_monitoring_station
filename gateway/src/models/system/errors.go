package system

import "fmt"

type ErrType string

const (
	KafkaErr          ErrType = "KafkaErr"
	RedisErr          ErrType = "RedisErr"
	CircuitErr        ErrType = "CircuitErr"
	EtcdErr           ErrType = "EtcdErr"
	SessionServiceErr ErrType = "SessionServiceErr"
	AdapterErr        ErrType = "AdapterErr"
	RegistryErr       ErrType = "RegistryErr"
	MySQLErr          ErrType = "MySQLErr"
	AppErr            ErrType = "AppErr"
	UsecaseErr        ErrType = "UsecaseErr"
	RateLimitErr      ErrType = "RateLimitErr"
	CryptoErr         ErrType = "CryptoErr"
	GRPCErr           ErrType = "GRPCErr"
	AuthErr           ErrType = "AuthErr"
	CommSecErr        ErrType = "CommSecErr"
)

// Error 定义了一个通用的错误结构体，包含错误类型和详细信息。
type Error struct {
	ErrType ErrType
	Info    string
}

func (e *Error) Error() string {
	return string(e.ErrType) + ": " + e.Info
}

func NewError(errType ErrType, info string) *Error {
	return &Error{ErrType: errType, Info: info}
}

var (
	ErrNilMySQLClient    Error = *NewError(MySQLErr, "mysql client is nil")
	ErrMySQLConfigNeeded Error = *NewError(MySQLErr, "mysql config is required")
	ErrMySQLDSNRequired  Error = *NewError(MySQLErr, "mysql dsn is required")
	ErrMySQLNoAvailable  Error = *NewError(MySQLErr, "no mysql instance is available")
	ErrTxFuncNil         Error = *NewError(MySQLErr, "transaction func is nil")
)

var (
	ErrCircuitOpen      Error = *NewError(CircuitErr, "circuit breaker is open")
	ErrHalfOpenMaxCalls Error = *NewError(CircuitErr, "circuit breaker half-open max calls reached")
	ErrCallFuncNil      Error = *NewError(CircuitErr, "call func is nil")
	ErrNoCircuitBreaker Error = *NewError(CircuitErr, "circuit breaker is nil")
)

var (
	ErrBrokersRequired Error = *NewError(KafkaErr, "kafka brokers are required")
	ErrTopicRequired   Error = *NewError(KafkaErr, "topic is required")
	ErrGroupIDRequired Error = *NewError(KafkaErr, "groupID is required")
)

var (
	ErrNilEtcdClient     Error = *NewError(EtcdErr, "etcd client is nil")
	ErrEndpointsRequired Error = *NewError(EtcdErr, "etcd endpoints are required")
	ErrNilEndpoints      Error = *NewError(EtcdErr, "no etcd endpoints available")
	ErrLockNameRequired  Error = *NewError(EtcdErr, "lock name is required")
)

var (
	ErrNilRedisClient     Error = *NewError(RedisErr, "redis client is nil")
	ErrNoConfig           Error = *NewError(RedisErr, "redis config is required")
	ErrAddrRequired       Error = *NewError(RedisErr, "redis address is required for standalone mode")
	ErrMasterNameRequired Error = *NewError(RedisErr, "redis master name is required for sentinel mode")
	ErrorUnsupportedMode  Error = *NewError(RedisErr, "unsupported redis mode")
)

var (
	ErrSessionIdRequired  Error = *NewError(SessionServiceErr, "session id is required")
	ErrNegativeSessionTTL Error = *NewError(SessionServiceErr, "ttl must be greater than 0")
	ErrorSessionNotFound  Error = *NewError(SessionServiceErr, "session not found")
)

var (
	ErrorNegativeEtcdTTL    Error = *NewError(AdapterErr, "ttl must be greater than 0")
	ErrNilRegistryClient    Error = *NewError(AdapterErr, "registry client is nil")
	ErrNoAvaliableInstances Error = *NewError(AdapterErr, "no service instances available")
	ErrNoMatchingTags       Error = *NewError(AdapterErr, "no service instances match required tags")
	ErrInvalidInstance      Error = *NewError(AdapterErr, "selected service instance is invalid")
)

var (
	ErrInstanceNameOrIdRequired Error = *NewError(RegistryErr, "service instance name and id are required")
	ErrServiceNameRequired      Error = *NewError(AdapterErr, "service name is required")
)

var (
	ErrGatewayAppDependenciesRequired Error = *NewError(AppErr, "gateway app dependencies are required")
)

var (
	ErrGRPCOutboundDependenciesRequired Error = *NewError(GRPCErr, "grpc outbound dependencies are required")
	ErrForwardRequestNil                Error = *NewError(GRPCErr, "forward request is nil")
	ErrEndpointRequired                 Error = *NewError(GRPCErr, "endpoint is required")
	ErrGRPCMethodRequired               Error = *NewError(GRPCErr, "grpc method is required")
	ErrGRPCInvokeFailed                 Error = *NewError(GRPCErr, "grpc invoke failed")
)

var (
	ErrOutboundSecurityDependenciesRequired Error = *NewError(UsecaseErr, "outbound security dependencies are required")
	ErrOutboundInvocationRequestInvalid     Error = *NewError(UsecaseErr, "outbound invocation request is invalid")
	ErrForwardingDependenciesRequired       Error = *NewError(UsecaseErr, "forwarding dependencies are required")
	ErrForwardingRequestInvalid             Error = *NewError(UsecaseErr, "forwarding request is invalid")
	ErrBootstrapCoordinatorRequired         Error = *NewError(UsecaseErr, "bootstrap coordinator is required")
	ErrReadinessRequestInvalid              Error = *NewError(UsecaseErr, "readiness request is invalid")
	ErrResolverDependenciesRequired         Error = *NewError(UsecaseErr, "resolver dependencies are required")
	ErrResolveTargetRequestNil              Error = *NewError(UsecaseErr, "resolve target request is nil")
	ErrRouteRuleNotFound                    Error = *NewError(UsecaseErr, "route rule not found")
)

var (
	ErrBootstrapClientRequired       Error = *NewError(AuthErr, "bootstrap client is required")
	ErrDownstreamGrantClientRequired Error = *NewError(AuthErr, "downstream grant client is required")
	ErrChallengeSignerRequired       Error = *NewError(AuthErr, "challenge signer is required")
	ErrSessionServiceNotConfigured   Error = *NewError(AuthErr, "session service is not configured")
	ErrSessionNotFound               Error = *NewError(AuthErr, "session not found")
	ErrSessionNotActive              Error = *NewError(AuthErr, "session is not active")
	ErrSessionValidateRequestNil     Error = *NewError(AuthErr, "session validate request is nil")
	ErrSessionPrincipalMismatch      Error = *NewError(AuthErr, "session principal mismatch")
	ErrSessionVersionStale           Error = *NewError(AuthErr, "session version is stale")
	ErrSessionExpired                Error = *NewError(AuthErr, "session expired")
	ErrTokenManagerNotConfigured     Error = *NewError(AuthErr, "token manager is not configured")
	ErrAccessTokenNotAvailable       Error = *NewError(AuthErr, "access token is not available")
	ErrRefreshTokenRequired          Error = *NewError(AuthErr, "refresh token is required")
	ErrRefreshTokenNotFound          Error = *NewError(AuthErr, "refresh token not found")
	ErrRefreshTokenExpired           Error = *NewError(AuthErr, "refresh token expired")
	ErrRefreshTokenRevoked           Error = *NewError(AuthErr, "refresh token revoked")
	ErrTokenFamilyRevoked            Error = *NewError(AuthErr, "token family revoked")
	ErrRawTokenRequired              Error = *NewError(AuthErr, "raw token is required")
	ErrTokenRevokeRequestNil         Error = *NewError(AuthErr, "token revoke request is nil")
	ErrTokenIDOrFamilyIDRequired     Error = *NewError(AuthErr, "token id or family id is required")
	ErrChallengeRequestNil           Error = *NewError(AuthErr, "challenge request is nil")
	ErrEntityIDAndKeyIDRequired      Error = *NewError(AuthErr, "entity id and key id are required")
	ErrBootstrapAuthRequestNil       Error = *NewError(AuthErr, "bootstrap auth request is nil")
	ErrChallengeNotFound             Error = *NewError(AuthErr, "challenge not found")
	ErrChallengeExpired              Error = *NewError(AuthErr, "challenge expired")
	ErrChallengeResponseMismatch     Error = *NewError(AuthErr, "challenge response mismatch")
	ErrDownstreamGrantRequestNil     Error = *NewError(AuthErr, "downstream grant request is nil")
	ErrIdentityPrincipalRequired     Error = *NewError(AuthErr, "identity principal is required")
	ErrTargetServiceRequired         Error = *NewError(AuthErr, "target service is required")
)

var (
	ErrCommSecurityServiceRequired       Error = *NewError(CommSecErr, "comm security service is required")
	ErrLocalPublicKeyNotConfigured       Error = *NewError(CommSecErr, "local public key is not configured")
	ErrLocalPrivateKeyRefNotConfigured   Error = *NewError(CommSecErr, "local private key ref is not configured")
	ErrKeyIDRequired                     Error = *NewError(CommSecErr, "key id is required")
	ErrHandshakeInitRequestNil           Error = *NewError(CommSecErr, "handshake init request is nil")
	ErrInitiatorResponderServiceRequired Error = *NewError(CommSecErr, "initiator and responder service id are required")
	ErrHandshakeCompleteRequestNil       Error = *NewError(CommSecErr, "handshake complete request is nil")
	ErrHandshakeNotFound                 Error = *NewError(CommSecErr, "handshake not found")
	ErrHandshakeStateInvalid             Error = *NewError(CommSecErr, "handshake state is invalid")
	ErrHandshakeExpired                  Error = *NewError(CommSecErr, "handshake expired")
	ErrChannelEnsureRequestNil           Error = *NewError(CommSecErr, "channel ensure request is nil")
	ErrHandshakeInitRequired             Error = *NewError(CommSecErr, "handshake init is required when channel unavailable")
	ErrChannelUpsertRequestNil           Error = *NewError(CommSecErr, "channel upsert request is nil")
	ErrChannelQueryNil                   Error = *NewError(CommSecErr, "channel query is nil")
	ErrChannelNotFound                   Error = *NewError(CommSecErr, "channel not found")
	ErrChannelRevokeRequestNil           Error = *NewError(CommSecErr, "channel revoke request is nil")
	ErrChannelEncryptRequestNil          Error = *NewError(CommSecErr, "channel encrypt request is nil")
	ErrChannelDecryptRequestNil          Error = *NewError(CommSecErr, "channel decrypt request is nil")
	ErrChannelNotActive                  Error = *NewError(CommSecErr, "channel is not active")
	ErrChannelExpired                    Error = *NewError(CommSecErr, "channel expired")
	ErrMessageSequenceStale              Error = *NewError(CommSecErr, "message sequence is stale")
	ErrEmptyDerivedKeyRef                Error = *NewError(CommSecErr, "empty derived key ref")
)

var (
	ErrRateLimitDependenciesRequired Error = *NewError(RateLimitErr, "ratelimit dependencies are required")
	ErrRateLimitRequestInvalid       Error = *NewError(RateLimitErr, "ratelimit request is invalid")
	ErrInboundRateLimitInputNil      Error = *NewError(RateLimitErr, "inbound ratelimit input is nil")
	ErrRequestRateLimited            Error = *NewError(RateLimitErr, "request is rate limited")
)

var (
	ErrUnsupportedSymmetricKeySize   Error = *NewError(CryptoErr, "unsupported symmetric key size")
	ErrUnsupportedAsymmetricKeySize  Error = *NewError(CryptoErr, "unsupported asymmetric key size")
	ErrInvalidCiphertextLength       Error = *NewError(CryptoErr, "invalid ciphertext length")
	ErrUnsupportedCipherSuite        Error = *NewError(CryptoErr, "unsupported cipher suite")
	ErrInvalidPublicKeyPEM           Error = *NewError(CryptoErr, "invalid public key pem")
	ErrPublicKeyNotRSA               Error = *NewError(CryptoErr, "public key is not rsa")
	ErrInvalidPrivateKeyPEM          Error = *NewError(CryptoErr, "invalid private key pem")
	ErrPrivateKeyNotRSA              Error = *NewError(CryptoErr, "private key is not rsa")
	ErrPrivateKeyNotEd25519          Error = *NewError(CryptoErr, "private key is not ed25519")
	ErrPrivateKeyNotECDSA            Error = *NewError(CryptoErr, "private key is not ecdsa")
	ErrUnsupportedSignatureAlgorithm Error = *NewError(CryptoErr, "unsupported signature algorithm")
	ErrPublicKeyNotEd25519           Error = *NewError(CryptoErr, "public key is not ed25519")
	ErrPublicKeyNotECDSA             Error = *NewError(CryptoErr, "public key is not ecdsa")
	ErrSignatureVerificationFailed   Error = *NewError(CryptoErr, "signature verification failed")
	ErrUnsupportedPrivateKeyFormat   Error = *NewError(CryptoErr, "unsupported private key format")
	ErrUnsupportedPublicKeyType      Error = *NewError(CryptoErr, "unsupported public key type")
)

var (
	ErrCircuitProtectedCallPanic Error = *NewError(CircuitErr, "circuit breaker protected call panic")
	ErrKafkaCloseWriterFailed    Error = *NewError(KafkaErr, "close writer failed")
	ErrKafkaCloseReaderFailed    Error = *NewError(KafkaErr, "close reader failed")
	ErrRegistryInstanceMarshal   Error = *NewError(RegistryErr, "marshal instance failed")
)

func Wrap(base *Error, err error) error {
	if base == nil {
		return err
	}
	if err == nil {
		return base
	}
	return fmt.Errorf("%w: %v", base, err)
}
