package utils

import (
	modelsystem "certification_server/src/models/system"
	"context"
	"fmt"
	"sync"
	"time"
)

type CircuitBreakerState string

const (
	StateClosed   CircuitBreakerState = "closed"
	StateOpen     CircuitBreakerState = "open"
	StateHalfOpen CircuitBreakerState = "half_open"
)

// CircuitBreaker 定义了简单的熔断器结构体实现。
type CircuitBreaker struct {
	Name             string
	State            CircuitBreakerState
	cfg              modelsystem.CircuitBreakerConfig
	mu               sync.Mutex
	failureCount     int
	lastFailureTime  time.Time
	halfOpenInFlight int
}

// NewCircuitBreaker 创建一个新的 CircuitBreaker 实例。
func NewCircuitBreaker(name string, cfg *modelsystem.CircuitBreakerConfig) *CircuitBreaker {
	finalCfg := defaultCircuitBreakerConfig()
	if cfg != nil {
		if cfg.FailureThreshold > 0 {
			finalCfg.FailureThreshold = cfg.FailureThreshold
		}
		if cfg.RecoveryTimeout > 0 {
			finalCfg.RecoveryTimeout = cfg.RecoveryTimeout
		}
		if cfg.HalfOpenMaxCalls > 0 {
			finalCfg.HalfOpenMaxCalls = cfg.HalfOpenMaxCalls
		}
	}

	return &CircuitBreaker{
		Name:  name,
		State: StateClosed,
		cfg:   finalCfg,
	}
}

// Call 提供最简调用入口，适合不需要返回值的业务函数。
func (cb *CircuitBreaker) Call(ctx context.Context, fun func()) (any, error) {
	if fun == nil {
		return nil, &modelsystem.ErrCallFuncNil
	}
	return cb.CallWithResult(ctx, func(context.Context) (any, error) {
		fun()
		return nil, nil
	})
}

// CallWithResult 提供带结果和错误返回的调用入口。
func (cb *CircuitBreaker) CallWithResult(
	ctx context.Context,
	fun func(context.Context) (any, error),
) (result any, err error) {
	if cb == nil {
		return nil, &modelsystem.ErrNoCircuitBreaker
	}
	if fun == nil {
		return nil, &modelsystem.ErrCallFuncNil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	if err = cb.beforeCall(time.Now()); err != nil {
		return nil, err
	}

	defer func() {
		if r := recover(); r != nil {
			cb.recordFailure(time.Now())
			err = fmt.Errorf("%w: %v", &modelsystem.ErrCircuitProtectedCallPanic, r)
			result = nil
		}
	}()

	if ctx.Err() != nil {
		cb.recordFailure(time.Now())
		return nil, ctx.Err()
	}

	result, err = fun(ctx)
	if err != nil {
		cb.recordFailure(time.Now())
		return nil, err
	}

	cb.recordSuccess()
	return result, nil
}

// CurrentState 返回熔断器当前状态。
func (cb *CircuitBreaker) CurrentState() CircuitBreakerState {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.State
}

func (cb *CircuitBreaker) beforeCall(now time.Time) error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.State {
	case StateOpen:
		if now.Sub(cb.lastFailureTime) < cb.cfg.RecoveryTimeout {
			return &modelsystem.ErrCircuitOpen
		}
		cb.State = StateHalfOpen
		cb.halfOpenInFlight = 0
		cb.failureCount = 0
		cb.halfOpenInFlight++
		return nil
	case StateHalfOpen:
		if cb.halfOpenInFlight >= cb.cfg.HalfOpenMaxCalls {
			return &modelsystem.ErrHalfOpenMaxCalls
		}
		cb.halfOpenInFlight++
		return nil
	default:
		return nil
	}
}

func (cb *CircuitBreaker) recordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.State == StateHalfOpen {
		cb.halfOpenInFlight = maxInt(0, cb.halfOpenInFlight-1)
		// 简易实现: 半开探测一旦成功，直接恢复闭合。
		cb.State = StateClosed
		cb.failureCount = 0
		cb.lastFailureTime = time.Time{}
		cb.halfOpenInFlight = 0
		return
	}

	cb.failureCount = 0
}

func (cb *CircuitBreaker) recordFailure(now time.Time) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.State == StateHalfOpen {
		cb.halfOpenInFlight = maxInt(0, cb.halfOpenInFlight-1)
		cb.State = StateOpen
		cb.failureCount = cb.cfg.FailureThreshold
		cb.lastFailureTime = now
		return
	}

	cb.failureCount++
	if cb.failureCount >= cb.cfg.FailureThreshold {
		cb.State = StateOpen
		cb.lastFailureTime = now
	}
}

func defaultCircuitBreakerConfig() modelsystem.CircuitBreakerConfig {
	return modelsystem.CircuitBreakerConfig{
		FailureThreshold: 5,
		RecoveryTimeout:  10 * time.Second,
		HalfOpenMaxCalls: 1,
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
