package ratelimit

import (
	"context"

	ratelimitif "gateway/src/interfaces/ratelimit"
	authmodel "gateway/src/models/auth"
	modelsystem "gateway/src/models/system"
)

// ErrRateLimited 表示请求被限流拒绝。
var ErrRateLimited = &modelsystem.ErrRequestRateLimited

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
		return nil, &modelsystem.ErrRateLimitDependenciesRequired
	}
	if req == nil || req.Input == nil {
		return nil, &modelsystem.ErrRateLimitRequestInvalid
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
