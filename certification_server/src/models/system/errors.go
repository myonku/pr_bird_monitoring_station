package system

type ErrType string

const (
	KafkaErr          ErrType = "KafkaErr"
	RedisErr          ErrType = "RedisErr"
	MySQLErr          ErrType = "MySQLErr"
	CircuitErr        ErrType = "CircuitErr"
	EtcdErr           ErrType = "EtcdErr"
	SessionServiceErr ErrType = "SessionServiceErr"
	AdapterErr        ErrType = "AdapterErr"
	RegistryErr       ErrType = "RegistryErr"
	AppErr            ErrType = "AppErr"
	AuthErr           ErrType = "AuthErr"
	CommSecErr        ErrType = "CommSecErr"
	RateLimitErr      ErrType = "RateLimitErr"
	GRPCErr           ErrType = "GRPCErr"
	CryptoErr         ErrType = "CryptoErr"
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
	ErrNilEtcdClient     Error = *NewError(EtcdErr, "etcd client is nil")
	ErrEndpointsRequired Error = *NewError(EtcdErr, "etcd endpoints are required")
	ErrNilEndpoints      Error = *NewError(EtcdErr, "no etcd endpoints available")
	ErrLockNameRequired  Error = *NewError(EtcdErr, "lock name is required")
)

var (
	ErrorNegativeEtcdTTL    Error = *NewError(AdapterErr, "ttl must be greater than 0")
	ErrNilRegistryClient    Error = *NewError(AdapterErr, "registry client is nil")
	ErrNoAvaliableInstances Error = *NewError(AdapterErr, "no service instances available")
	ErrNoMatchingTags       Error = *NewError(AdapterErr, "no service instances match required tags")
	ErrInvalidInstance      Error = *NewError(AdapterErr, "selected service instance is invalid")
)

var (
	ErrNilRedisClient     Error = *NewError(RedisErr, "redis client is nil")
	ErrNoConfig           Error = *NewError(RedisErr, "redis config is required")
	ErrAddrRequired       Error = *NewError(RedisErr, "redis address is required for standalone mode")
	ErrMasterNameRequired Error = *NewError(RedisErr, "redis master name is required for sentinel mode")
	ErrorUnsupportedMode  Error = *NewError(RedisErr, "unsupported redis mode")
)

var (
	ErrNilMySQLClient    Error = *NewError(MySQLErr, "mysql client is nil")
	ErrMySQLConfigNeeded Error = *NewError(MySQLErr, "mysql config is required")
	ErrMySQLDSNRequired  Error = *NewError(MySQLErr, "mysql dsn is required")
	ErrMySQLNoAvailable  Error = *NewError(MySQLErr, "no mysql instance is available")
	ErrTxFuncNil         Error = *NewError(MySQLErr, "transaction func is nil")
)

var (
	ErrCircuitOpen               Error = *NewError(CircuitErr, "circuit breaker is open")
	ErrHalfOpenMaxCalls          Error = *NewError(CircuitErr, "circuit breaker half-open max calls reached")
	ErrCallFuncNil               Error = *NewError(CircuitErr, "call func is nil")
	ErrNoCircuitBreaker          Error = *NewError(CircuitErr, "circuit breaker is nil")
	ErrCircuitProtectedCallPanic Error = *NewError(CircuitErr, "circuit breaker protected call panic")
)

var (
	ErrAppDependenciesRequired Error = *NewError(AppErr, "certification app dependencies are required")
)

var (
	ErrInstanceNameOrIdRequired Error = *NewError(RegistryErr, "service instance name and id are required")
	ErrServiceNameRequired      Error = *NewError(AdapterErr, "service name is required")
)

var (
	ErrRateLimited                            Error = *NewError(RateLimitErr, "request is rate limited")
	ErrRateLimitDependenciesNil               Error = *NewError(RateLimitErr, "ratelimit dependencies are required")
	ErrRateLimitRequestInvalid                Error = *NewError(RateLimitErr, "ratelimit request is invalid")
	ErrInboundRateLimitInputNil               Error = *NewError(RateLimitErr, "inbound ratelimit input is nil")
	ErrRoutingInputRequired                   Error = *NewError(AdapterErr, "routing input is required")
	ErrRouteProfileNotFound                   Error = *NewError(AdapterErr, "route profile is not found")
	ErrTrafficInboundRequestInvalid           Error = *NewError(AdapterErr, "traffic inbound request is invalid")
	ErrTrafficStationDependenciesRequired     Error = *NewError(AdapterErr, "traffic station dependencies are required")
	ErrGRPCMethodInfoNil                      Error = *NewError(GRPCErr, "grpc method info is nil")
	ErrBootstrapRPCDependenciesRequired       Error = *NewError(GRPCErr, "bootstrap rpc dependencies are required")
	ErrGRPCServerAlreadyStarted               Error = *NewError(GRPCErr, "grpc server already started")
	ErrRedisNotConfigured                     Error = *NewError(RedisErr, "redis not configured")
	ErrMySQLNotConfigured                     Error = *NewError(MySQLErr, "mysql not configured")
	ErrTokenIssueRequestNil                   Error = *NewError(AuthErr, "token issue request is nil")
	ErrPrincipalRequired                      Error = *NewError(AuthErr, "principal is required")
	ErrSessionNil                             Error = *NewError(AuthErr, "session is nil")
	ErrRefreshTokenRequired                   Error = *NewError(AuthErr, "refresh token is required")
	ErrRefreshTokenNotFound                   Error = *NewError(AuthErr, "refresh token not found")
	ErrTokenNotRefreshType                    Error = *NewError(AuthErr, "token is not refresh type")
	ErrRefreshTokenNotActive                  Error = *NewError(AuthErr, "refresh token is not active")
	ErrRawTokenRequired                       Error = *NewError(AuthErr, "raw token is required")
	ErrTokenRevokeRequestNil                  Error = *NewError(AuthErr, "token revoke request is nil")
	ErrTokenIDOrFamilyIDRequired              Error = *NewError(AuthErr, "token id or family id is required")
	ErrFamilyIDRequired                       Error = *NewError(AuthErr, "family id is required")
	ErrSessionIssueRequestNil                 Error = *NewError(AuthErr, "session issue request is nil")
	ErrSessionNotFound                        Error = *NewError(AuthErr, "session not found")
	ErrSessionNotActive                       Error = *NewError(AuthErr, "session is not active")
	ErrSessionValidateRequestNil              Error = *NewError(AuthErr, "session validate request is nil")
	ErrSessionPrincipalMismatch               Error = *NewError(AuthErr, "session principal mismatch")
	ErrSessionVersionStale                    Error = *NewError(AuthErr, "session version is stale")
	ErrSessionExpired                         Error = *NewError(AuthErr, "session expired")
	ErrSessionRevokeRequestNil                Error = *NewError(AuthErr, "session revoke request is nil")
	ErrPrincipalIDRequired                    Error = *NewError(AuthErr, "principal id is required")
	ErrChallengeRequestNil                    Error = *NewError(AuthErr, "challenge request is nil")
	ErrEntityIDAndKeyIDRequired               Error = *NewError(AuthErr, "entity id and key id are required")
	ErrBootstrapAuthRequestNil                Error = *NewError(AuthErr, "bootstrap auth request is nil")
	ErrChallengeNotFound                      Error = *NewError(AuthErr, "challenge not found")
	ErrChallengeExpired                       Error = *NewError(AuthErr, "challenge expired")
	ErrChallengeResponseMismatch              Error = *NewError(AuthErr, "challenge response mismatch")
	ErrPublicKeyNotFoundForKeyID              Error = *NewError(AuthErr, "public key not found for key id")
	ErrPublicKeyNotFoundForEntityID           Error = *NewError(AuthErr, "public key not found for entity id")
	ErrSignatureAlgorithmRequired             Error = *NewError(AuthErr, "signature algorithm is required")
	ErrSignatureAlgorithmMismatch             Error = *NewError(AuthErr, "signature algorithm mismatch with key catalog")
	ErrAuthGatewayOrchestratorDepsRequired    Error = *NewError(AuthErr, "auth gateway orchestrator dependencies are required")
	ErrAuthGatewayChannelDependenciesRequired Error = *NewError(AuthErr, "auth gateway channel dependencies are required")
	ErrBootstrapDepsNotReady                  Error = *NewError(AuthErr, "bootstrap dependencies are not ready")
	ErrUserCredentialDepsNotReady             Error = *NewError(AuthErr, "user credential auth dependencies are not ready")
	ErrUserPasswordAuthRequestNil             Error = *NewError(AuthErr, "user password auth request is nil")
	ErrUsernameRequired                       Error = *NewError(AuthErr, "username is required")
	ErrPasswordRequired                       Error = *NewError(AuthErr, "password is required")
	ErrInvalidUserCredentials                 Error = *NewError(AuthErr, "invalid user credentials")
	ErrEntityIDRequired                       Error = *NewError(AuthErr, "entity id is required")
	ErrDownstreamGrantRequestNil              Error = *NewError(AuthErr, "downstream grant request is nil")
	ErrIdentityPrincipalRequired              Error = *NewError(AuthErr, "identity principal is required")
	ErrTargetServiceRequired                  Error = *NewError(AuthErr, "target service is required")
	ErrCommSecurityServiceRequired            Error = *NewError(CommSecErr, "comm security service is required")
	ErrLocalPublicKeyNotConfigured            Error = *NewError(CommSecErr, "local public key is not configured")
	ErrLocalPrivateKeyRefNotConfigured        Error = *NewError(CommSecErr, "local private key ref is not configured")
	ErrPublicKeyLookupRequestNil              Error = *NewError(CommSecErr, "public key lookup request is nil")
	ErrPublicKeyLookupCriteriaRequired        Error = *NewError(CommSecErr, "public key lookup criteria is required")
	ErrKeyIDRequired                          Error = *NewError(CommSecErr, "key id is required")
	ErrSecretKeyServiceNotConfigured          Error = *NewError(CommSecErr, "secret key service is not configured")
	ErrUnsupportedSymmetricKeySize            Error = *NewError(CryptoErr, "unsupported symmetric key size")
	ErrUnsupportedAsymmetricKeySize           Error = *NewError(CryptoErr, "unsupported asymmetric key size")
	ErrInvalidCiphertextLength                Error = *NewError(CryptoErr, "invalid ciphertext length")
	ErrUnsupportedCipherSuite                 Error = *NewError(CryptoErr, "unsupported cipher suite")
	ErrInvalidPublicKeyPEM                    Error = *NewError(CryptoErr, "invalid public key pem")
	ErrPublicKeyNotRSA                        Error = *NewError(CryptoErr, "public key is not rsa")
	ErrInvalidPrivateKeyPEM                   Error = *NewError(CryptoErr, "invalid private key pem")
	ErrPrivateKeyNotRSA                       Error = *NewError(CryptoErr, "private key is not rsa")
	ErrPrivateKeyNotEd25519                   Error = *NewError(CryptoErr, "private key is not ed25519")
	ErrPrivateKeyNotECDSA                     Error = *NewError(CryptoErr, "private key is not ecdsa")
	ErrUnsupportedSignatureAlgorithm          Error = *NewError(CryptoErr, "unsupported signature algorithm")
	ErrPublicKeyNotEd25519                    Error = *NewError(CryptoErr, "public key is not ed25519")
	ErrPublicKeyNotECDSA                      Error = *NewError(CryptoErr, "public key is not ecdsa")
	ErrSignatureVerificationFailed            Error = *NewError(CryptoErr, "signature verification failed")
	ErrUnsupportedPrivateKeyFormat            Error = *NewError(CryptoErr, "unsupported private key format")
	ErrUnsupportedPublicKeyType               Error = *NewError(CryptoErr, "unsupported public key type")
)

var (
	ErrKafkaCloseWriterFailed  Error = *NewError(KafkaErr, "close writer failed")
	ErrKafkaCloseReaderFailed  Error = *NewError(KafkaErr, "close reader failed")
	ErrRegistryInstanceMarshal Error = *NewError(RegistryErr, "marshal instance failed")
)
