package system

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
