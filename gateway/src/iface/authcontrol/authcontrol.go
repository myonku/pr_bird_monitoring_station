package authcontrol

import (
	"context"

	authmodel "gateway/src/models/auth"
)

// InboundAuthRequest 是网关入站认证控制请求。
type InboundAuthRequest struct {
	TokenVerifyRequest     *TokenVerifyRequest
	SessionValidateRequest *SessionValidateRequest
	RateLimitInput         *InboundRateLimitInput
}

// InboundAuthResult 是网关入站认证控制结果。
type InboundAuthResult struct {
	Identity          *authmodel.IdentityContext
	Session           *authmodel.Session
	TokenVerification *authmodel.TokenVerificationResult
	RateLimitDecision *authmodel.RateLimitDecision
}

// OutboundAuthRequest 是网关出站授权+限流请求。
type OutboundAuthRequest struct {
	Identity *authmodel.IdentityContext

	TargetService string
	TTLSec        int64

	RateLimitInput *InboundRateLimitInput
}

// OutboundAuthResult 是网关出站授权+限流结果。
type OutboundAuthResult struct {
	Grant             *authmodel.DownstreamAccessGrant
	RateLimitDecision *authmodel.RateLimitDecision
	GrantStateKey     string
}

// IGatewayAuthControl 定义网关认证与限流控制点。
//
// 下游接口调用：
//   - authcontrol.IAuthAuthorityClient.VerifyToken / ValidateSession / IssueDownstreamGrant
//   - authcontrol.IDescriptorFactory.Build
//   - authcontrol.IRateLimiter.Decide
//   - common.IGrantStateManager.SaveGrant（可选路径）
type IGatewayAuthControl interface {
	EnforceInbound(ctx context.Context, req *InboundAuthRequest) (*InboundAuthResult, error)
	PrepareOutbound(ctx context.Context, req *OutboundAuthRequest) (*OutboundAuthResult, error)
}
