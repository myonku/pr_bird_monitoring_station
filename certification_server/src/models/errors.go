package models

type ErrType string

const (
	KafkaErr          ErrType = "KafkaErr"
	RedisErr          ErrType = "RedisErr"
	CircuitErr        ErrType = "CircuitErr"
	EtcdErr           ErrType = "EtcdErr"
	SessionServiceErr ErrType = "SessionServiceErr"
	AdapterErr        ErrType = "AdapterErr"
	RegistryErr       ErrType = "RegistryErr"
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
	ErrNilRedisClient     Error = *NewError(RedisErr, "redis client is nil")
	ErrNoConfig           Error = *NewError(RedisErr, "redis config is required")
	ErrAddrRequired       Error = *NewError(RedisErr, "redis address is required for standalone mode")
	ErrMasterNameRequired Error = *NewError(RedisErr, "redis master name is required for sentinel mode")
	ErrorUnsupportedMode  Error = *NewError(RedisErr, "unsupported redis mode")
)

var (
	ErrCircuitOpen      Error = *NewError(CircuitErr, "circuit breaker is open")
	ErrHalfOpenMaxCalls Error = *NewError(CircuitErr, "circuit breaker half-open max calls reached")
	ErrCallFuncNil      Error = *NewError(CircuitErr, "call func is nil")
	ErrNoCircuitBreaker Error = *NewError(CircuitErr, "circuit breaker is nil")
)
