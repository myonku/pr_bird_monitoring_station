package authcontrol

import (
	"context"

	"github.com/google/uuid"

	authmodel "gateway/src/models/auth"
)

// AuthControlPurpose 表示一次认证控制请求的用途。
type AuthControlPurpose string

const (
	AuthControlPurposeInbound  AuthControlPurpose = "inbound"
	AuthControlPurposeOutbound AuthControlPurpose = "outbound"
)

// AuthorizationInput 表示外部 HTTP 层整理后的认证输入。
type AuthorizationInput struct {
	RawToken string

	SessionID     uuid.UUID
	PrincipalID   string
	RequireActive bool
	MinVersion    int64

	ExpectedTokenTypes  []authmodel.TokenType
	ExpectedAudience    string
	RequireScopes       []string
	AllowExpiredSkewSec int64
}

// RateLimitInput 表示认证控制使用的协议无关限流输入。
type RateLimitInput struct {
	Scope     authmodel.RateLimitScope
	Transport string

	Module string
	Action string
	Route  string
	Method string

	SourceIP  string
	GatewayID string
	ClientID  string

	SourceService string
	TargetService string

	Headers map[string]string
	Tags    map[string]string

	Identity *authmodel.IdentityContext
}

// AuthControlRequest 是网关统一认证控制请求。
type AuthControlRequest struct {
	Purpose AuthControlPurpose

	Authorization *AuthorizationInput
	RateLimit     *RateLimitInput
}

// AuthControlResult 是网关统一认证控制结果。
type AuthControlResult struct {
	Identity          *authmodel.IdentityContext
	Session           *authmodel.Session
	TokenVerification *authmodel.TokenVerificationResult
	RateLimitDecision *authmodel.RateLimitDecision
}

// IGatewayAuthControl 定义网关认证与限流控制点。
type IGatewayAuthControl interface {
	Enforce(ctx context.Context, req *AuthControlRequest) (*AuthControlResult, error)
}
