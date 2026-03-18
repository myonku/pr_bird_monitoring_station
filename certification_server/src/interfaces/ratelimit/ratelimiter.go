package ratelimit

import (
	authmodel "certification_server/src/models/auth"
	"context"
)

// IRateLimiter 定义统一限流决策端口，供 gRPC 拦截器复用。
type IRateLimiter interface {
	Decide(ctx context.Context, descriptor *authmodel.RateLimitDescriptor) (*authmodel.RateLimitDecision, error)
}

// InboundRateLimitInput 表示协议无关的入站限流输入。
type InboundRateLimitInput struct {
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

// IDescriptorFactory 负责把入站上下文转换为统一限流描述符。
type IDescriptorFactory interface {
	Build(input *InboundRateLimitInput) (*authmodel.RateLimitDescriptor, error)
}
