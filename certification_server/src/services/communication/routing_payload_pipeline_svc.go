package communication

import (
	"context"
	"strings"

	communicationif "certification_server/src/iface/communication"
	modelsystem "certification_server/src/models/system"
)

var _ communicationif.IRoutingPayloadPipeline = (*RoutingPayloadPipelineService)(nil)

const (
	remoteAuthVerifyRouteKey              = "auth.remote.verify.token"
	remoteSessionValidateRouteKey         = "auth.remote.validate.session"
	externalAuthForwardRouteKey           = "auth.external.forward.user_password"
	externalBootstrapChallengeRouteKey    = "auth.external.forward.bootstrap.challenge"
	externalBootstrapAuthenticateRouteKey = "auth.external.forward.bootstrap.authenticate"
)

const (
	routingBootstrapInitMethodPath                 = "/bms.auth.v1.AuthAuthorityBootstrapService/InitBootstrapChallenge"
	routingBootstrapAuthMethodPath                 = "/bms.auth.v1.AuthAuthorityBootstrapService/AuthenticateBootstrap"
	routingRemoteVerifyMethodPath                  = "/bms.auth.v1.AuthAuthorityRemoteAuthService/VerifyToken"
	routingSessionCheckMethodPath                  = "/bms.auth.v1.AuthAuthorityRemoteAuthService/ValidateSession"
	routingExternalAuthMethodPath                  = "/bms.auth.v1.AuthAuthorityExternalAuthService/ForwardUserPassword"
	routingExternalBootstrapChallengeMethodPath    = "/bms.auth.v1.AuthAuthorityExternalAuthService/ForwardBootstrapChallenge"
	routingExternalBootstrapAuthenticateMethodPath = "/bms.auth.v1.AuthAuthorityExternalAuthService/ForwardBootstrapAuthenticate"
)

// RoutingPayloadPipelineService 提供认证中心入站路由分类与策略构建能力。
type RoutingPayloadPipelineService struct{}

func NewRoutingPayloadPipelineService() communicationif.IRoutingPayloadPipeline {
	return &RoutingPayloadPipelineService{}
}

func (s *RoutingPayloadPipelineService) ResolveRouteProfile(
	ctx context.Context,
	input *communicationif.RoutingInput,
) (*communicationif.RouteProfile, error) {
	_ = ctx
	if input == nil {
		return nil, &modelsystem.ErrRoutingInputRequired
	}

	category, err := s.ClassifyFlow(ctx, input)
	if err != nil {
		return nil, err
	}

	operation := resolveInboundOperation(input, category)
	if operation == "" {
		return nil, &modelsystem.ErrRouteProfileNotFound
	}

	profile := &communicationif.RouteProfile{
		TargetServiceType: resolveTargetServiceType(category),
		TargetServiceName: resolveTargetServiceName(category),
		TargetEndpoint:    strings.TrimSpace(input.TargetServiceHint),
		FlowCategory:      category,
		SecurityPolicy:    resolveInboundSecurityPolicy(category),
		Operation:         operation,
		Metadata: map[string]string{
			"flow_category":       string(category),
			"operation":           operation,
			"target_service_type": resolveTargetServiceType(category),
			"target_service_name": resolveTargetServiceName(category),
		},
	}

	return profile, nil
}

func (s *RoutingPayloadPipelineService) ClassifyFlow(
	ctx context.Context,
	input *communicationif.RoutingInput,
) (communicationif.FlowCategory, error) {
	_ = ctx
	if input == nil {
		return "", &modelsystem.ErrRoutingInputRequired
	}

	if category, ok := parseFlowCategory(input.RouteKey); ok {
		return category, nil
	}

	if category, ok := parseStaticFlowCategory(input); ok {
		return category, nil
	}

	return "", &modelsystem.ErrRouteProfileNotFound
}

func (s *RoutingPayloadPipelineService) BuildInboundPolicy(
	ctx context.Context,
	input *communicationif.RoutingInput,
) (*communicationif.InboundPolicyPlan, error) {
	if input == nil {
		return nil, &modelsystem.ErrRoutingInputRequired
	}

	profile, err := s.ResolveRouteProfile(ctx, input)
	if err != nil {
		return nil, err
	}
	if profile == nil {
		return nil, &modelsystem.ErrRouteProfileNotFound
	}

	plan := &communicationif.InboundPolicyPlan{
		RouteProfile:   profile,
		RequiredScopes: resolveRequiredScopes(profile.FlowCategory),
		Tags: map[string]string{
			"flow_category": string(profile.FlowCategory),
			"operation":     profile.Operation,
		},
	}

	for key, value := range profile.Metadata {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		plan.Tags[key] = trimmed
	}

	return plan, nil
}

func parseFlowCategory(raw string) (communicationif.FlowCategory, bool) {
	resolved := strings.TrimSpace(strings.ToLower(raw))
	switch resolved {
	case bootstrapChallengeRouteKey, bootstrapAuthenticateRouteKey:
		return communicationif.FlowCategoryBootstrapCall, true
	case remoteAuthVerifyRouteKey, remoteSessionValidateRouteKey:
		return communicationif.FlowCategoryRemoteAuthVerify, true
	case externalAuthForwardRouteKey,
		externalBootstrapChallengeRouteKey,
		externalBootstrapAuthenticateRouteKey:
		return communicationif.FlowCategoryExternalAuth, true
	default:
		return "", false
	}
}

func parseStaticFlowCategory(input *communicationif.RoutingInput) (communicationif.FlowCategory, bool) {
	if input == nil {
		return "", false
	}
	if !strings.EqualFold(strings.TrimSpace(input.Transport), "grpc") {
		return "", false
	}
	if !strings.EqualFold(strings.TrimSpace(input.Method), "POST") {
		return "", false
	}
	switch strings.TrimSpace(strings.ToLower(input.Path)) {
	case strings.ToLower(routingBootstrapInitMethodPath), strings.ToLower(routingBootstrapAuthMethodPath):
		return communicationif.FlowCategoryBootstrapCall, true
	case strings.ToLower(routingRemoteVerifyMethodPath), strings.ToLower(routingSessionCheckMethodPath):
		return communicationif.FlowCategoryRemoteAuthVerify, true
	case strings.ToLower(routingExternalAuthMethodPath),
		strings.ToLower(routingExternalBootstrapChallengeMethodPath),
		strings.ToLower(routingExternalBootstrapAuthenticateMethodPath):
		return communicationif.FlowCategoryExternalAuth, true
	default:
		return "", false
	}
}

func resolveInboundOperation(
	input *communicationif.RoutingInput,
	category communicationif.FlowCategory,
) string {
	if input == nil {
		return ""
	}

	if input.Metadata != nil {
		if op := strings.TrimSpace(input.Metadata["operation"]); op != "" {
			return op
		}
		if grpcMethod := strings.TrimSpace(input.Metadata["grpc_method"]); grpcMethod != "" {
			return grpcMethod
		}
	}

	path := strings.TrimSpace(input.Path)
	if path != "" {
		if idx := strings.LastIndex(path, "/"); idx >= 0 && idx < len(path)-1 {
			return strings.TrimSpace(path[idx+1:])
		}
		return path
	}

	if routeKey := strings.TrimSpace(input.RouteKey); routeKey != "" {
		return routeKey
	}

	return string(category)
}

func resolveInboundSecurityPolicy(category communicationif.FlowCategory) communicationif.SecurityPolicy {
	switch category {
	case communicationif.FlowCategoryBootstrapCall:
		return communicationif.SecurityPolicyOptional
	case communicationif.FlowCategoryRemoteAuthVerify,
		communicationif.FlowCategoryExternalAuth:
		return communicationif.SecurityPolicyRequired
	default:
		return communicationif.SecurityPolicyOptional
	}
}

func resolveTargetServiceType(category communicationif.FlowCategory) string {
	switch category {
	case communicationif.FlowCategoryBootstrapCall,
		communicationif.FlowCategoryRemoteAuthVerify,
		communicationif.FlowCategoryExternalAuth:
		return "auth_authority"
	default:
		return "unknown"
	}
}

func resolveTargetServiceName(category communicationif.FlowCategory) string {
	switch category {
	case communicationif.FlowCategoryBootstrapCall,
		communicationif.FlowCategoryRemoteAuthVerify,
		communicationif.FlowCategoryExternalAuth:
		return "certification_server"
	default:
		return ""
	}
}

func resolveRequiredScopes(category communicationif.FlowCategory) []string {
	switch category {
	case communicationif.FlowCategoryBootstrapCall:
		return []string{"service:bootstrap"}
	case communicationif.FlowCategoryRemoteAuthVerify:
		return []string{"token:verify"}
	case communicationif.FlowCategoryExternalAuth:
		return []string{"user:authenticate"}
	default:
		return []string{}
	}
}
