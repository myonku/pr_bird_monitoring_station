package authcontrol

import (
	authmodel "certification_server/src/models/auth"
	modelsystem "certification_server/src/models/system"
	"context"
)

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

// Build 将入站输入转换为统一的限流描述符。
func Build(input *InboundRateLimitInput) (*authmodel.RateLimitDescriptor, error) {
	if input == nil {
		return nil, &modelsystem.ErrInboundRateLimitInputNil
	}

	descriptor := &authmodel.RateLimitDescriptor{
		Scope:         input.Scope,
		Transport:     input.Transport,
		Module:        input.Module,
		Action:        input.Action,
		Route:         input.Route,
		Method:        input.Method,
		SourceIP:      input.SourceIP,
		GatewayID:     input.GatewayID,
		ClientID:      input.ClientID,
		SourceService: input.SourceService,
		TargetService: input.TargetService,
		Tags:          input.Tags,
	}
	if descriptor.Tags == nil {
		descriptor.Tags = map[string]string{}
	}

	if input.Identity != nil {
		descriptor.Authenticated = true
		descriptor.EntityType = input.Identity.EntityType
		descriptor.EntityID = input.Identity.EntityID
		descriptor.PrincipalID = input.Identity.PrincipalID
		descriptor.SessionID = input.Identity.SessionID.String()
		descriptor.TokenID = input.Identity.TokenID.String()
		descriptor.TokenType = input.Identity.TokenType
		descriptor.Scopes = input.Identity.Scopes
	}

	return descriptor, nil
}

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
// 说明：
//   - 该门面只暴露入站控制结果，不再拆分独立的 rate-limit 能力接口层。
//   - 描述符构建与限流决策属于内部实现细节，不应向上层继续分叉。
type IInboundAuthControl interface {
	EnforceInbound(ctx context.Context, req *InboundControlRequest) (*InboundControlResult, error)
}
