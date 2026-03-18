package ratelimit

import (
	"errors"
	authmodel "gateway/src/models/auth"
)

// DefaultDescriptorFactory 是协议无关的默认描述符构建器。
type DefaultDescriptorFactory struct{}

// Build 将 InboundRateLimitInput 转为统一描述符。
func (f *DefaultDescriptorFactory) Build(input *InboundRateLimitInput) (*authmodel.RateLimitDescriptor, error) {
	if input == nil {
		return nil, errors.New("inbound ratelimit input is nil")
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
	} else {
		descriptor.Authenticated = false
	}

	return descriptor, nil
}
