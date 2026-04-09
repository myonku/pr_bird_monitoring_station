package authcontrol

import (
	"context"

	authmodel "certification_server/src/models/auth"
)

// IRateLimiter 定义 authcontrol 范围内的限流决策端口。
type IRateLimiter interface {
	Decide(ctx context.Context, descriptor *authmodel.RateLimitDescriptor) (*authmodel.RateLimitDecision, error)
}

// InboundRateLimitInput 是 authcontrol 使用的与协议无关的入站输入。
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

// IDescriptorFactory 根据入站上下文构建统一描述符。
type IDescriptorFactory interface {
	Build(input *InboundRateLimitInput) (*authmodel.RateLimitDescriptor, error)
}
