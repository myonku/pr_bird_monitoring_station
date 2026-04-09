package authcontrol

import (
	authmodel "certification_server/src/models/auth"
	modelsystem "certification_server/src/models/system"
)

// DefaultDescriptorFactory 是默认的与协议无关的描述符构建器。
type DefaultDescriptorFactory struct{}

// Build 将入站输入转换为统一的限流描述符。
func (f *DefaultDescriptorFactory) Build(input *InboundRateLimitInput) (*authmodel.RateLimitDescriptor, error) {
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
