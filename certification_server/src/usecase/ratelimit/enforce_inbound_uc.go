package ratelimit

import (
	"context"
	"errors"

	ratelimitif "certification_server/src/interfaces/ratelimit"
	authmodel "certification_server/src/models/auth"
)

// ErrRateLimited 表示请求被限流拒绝。
var ErrRateLimited = errors.New("request is rate limited")

// EnforceInboundRequest 是入站限流用例输入。
type EnforceInboundRequest struct {
	Input *ratelimitif.InboundRateLimitInput
}

// EnforceInboundUsecase 负责执行协议无关的入站限流。
type EnforceInboundUsecase struct {
	Factory ratelimitif.IDescriptorFactory
	Limiter ratelimitif.IRateLimiter
}

// Execute 生成描述符并执行限流决策。
func (u *EnforceInboundUsecase) Execute(
	ctx context.Context,
	req *EnforceInboundRequest,
) (*authmodel.RateLimitDecision, error) {
	if u == nil || u.Factory == nil || u.Limiter == nil {
		return nil, errors.New("ratelimit dependencies are required")
	}
	if req == nil || req.Input == nil {
		return nil, errors.New("ratelimit request is invalid")
	}

	descriptor, err := u.Factory.Build(req.Input)
	if err != nil {
		return nil, err
	}

	decision, err := u.Limiter.Decide(ctx, descriptor)
	if err != nil {
		return nil, err
	}
	if decision != nil && !decision.Allowed {
		return decision, ErrRateLimited
	}
	return decision, nil
}
