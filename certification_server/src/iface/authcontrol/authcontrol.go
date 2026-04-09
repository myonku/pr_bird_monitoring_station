package authcontrol

import (
	"context"

	authmodel "certification_server/src/models/auth"
)

// InboundControlRequest 是认证中心本地入站控制请求。
type InboundControlRequest struct {
	RateLimitInput *InboundRateLimitInput
}

// InboundControlResult 是认证中心本地入站控制结果。
type InboundControlResult struct {
	RateLimitDecision *authmodel.RateLimitDecision
}

// IInboundAuthControl 定义 certification_server 的本地入站认证控制。
//
// 下游接口调用：
//   - authcontrol.IDescriptorFactory.Build
//   - authcontrol.IRateLimiter.Decide
type IInboundAuthControl interface {
	EnforceInbound(ctx context.Context, req *InboundControlRequest) (*InboundControlResult, error)
}
