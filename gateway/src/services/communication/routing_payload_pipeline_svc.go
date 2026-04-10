package communication

import (
	"context"
	"strings"

	commonif "gateway/src/iface/common"
	communicationif "gateway/src/iface/communication"
	modelsystem "gateway/src/models/system"
)

var _ communicationif.IRoutingPayloadPipeline = (*RoutingPayloadPipelineService)(nil)

const (
	bootstrapChallengeRouteKey    = "auth.bootstrap.challenge"
	bootstrapAuthenticateRouteKey = "auth.bootstrap.authenticate"
	remoteAuthVerifyRouteKey      = "auth.remote.verify.token"
	remoteSessionValidateRouteKey = "auth.remote.validate.session"
	externalAuthForwardRouteKey   = "auth.external.forward.user_password"
	businessForwardRouteKey       = "business.forward.generic"
	targetReverifyRouteKey        = "auth.target.reverify.forwarded_context"
	bootstrapInitMethodPath       = "/bms.auth.v1.AuthAuthorityBootstrapService/InitBootstrapChallenge"
	bootstrapAuthMethodPath       = "/bms.auth.v1.AuthAuthorityBootstrapService/AuthenticateBootstrap"
)

// RoutingPayloadPipelineService 提供网关通信下层最小可运行实现。
type RoutingPayloadPipelineService struct {
	resolverSvc commonif.IServiceResolver
}

func NewRoutingPayloadPipelineService(
	resolverSvc commonif.IServiceResolver,
) communicationif.IRoutingPayloadPipeline {
	return &RoutingPayloadPipelineService{
		resolverSvc: resolverSvc,
	}
}

func (s *RoutingPayloadPipelineService) ResolveRouteProfile(
	ctx context.Context,
	flow *commonif.FlowRouteInput,
) (*commonif.RouteProfile, error) {
	if flow == nil {
		return nil, &modelsystem.ErrResolveTargetRequestNil
	}
	if s.resolverSvc == nil {
		return nil, &modelsystem.ErrResolverDependenciesRequired
	}

	profile, err := s.resolverSvc.ResolveRouteProfile(ctx, flow)
	if err != nil {
		return nil, err
	}
	if profile == nil {
		return nil, &modelsystem.ErrRouteRuleNotFound
	}

	if profile.FlowCategory == "" {
		profile.FlowCategory, _ = s.ClassifyFlow(ctx, flow)
	}
	if profile.SecurityPolicy == "" {
		profile.SecurityPolicy = resolveRoutingSecurityPolicy(profile.FlowCategory)
	}
	if strings.TrimSpace(profile.TargetServiceName) == "" {
		return nil, &modelsystem.ErrRouteRuleNotFound
	}

	return profile, nil
}

func (s *RoutingPayloadPipelineService) ClassifyFlow(
	ctx context.Context,
	flow *commonif.FlowRouteInput,
) (commonif.FlowCategory, error) {
	_ = ctx
	if flow == nil {
		return "", &modelsystem.ErrResolveTargetRequestNil
	}

	if category, ok := resolveRouteKeyCategory(flow.RouteKey); ok {
		return category, nil
	}

	if category, ok := resolveStaticFlowCategory(flow); ok {
		return category, nil
	}

	return "", &modelsystem.ErrRouteRuleNotFound
}

func (s *RoutingPayloadPipelineService) BuildOutboundPayload(
	ctx context.Context,
	req *communicationif.BuildOutboundPayloadRequest,
) (*communicationif.OutboundPayloadPlan, error) {
	if req == nil || req.Flow == nil {
		return nil, &modelsystem.ErrOutboundInvocationRequestInvalid
	}

	profile, err := s.ResolveRouteProfile(ctx, req.Flow)
	if err != nil {
		return nil, err
	}

	target := req.PreferredTarget
	if target == nil && s.resolverSvc != nil {
		target, _ = s.resolverSvc.ResolveTargetInstance(ctx, req.Flow)
	}
	if target != nil && strings.TrimSpace(profile.TargetEndpoint) == "" {
		profile.TargetEndpoint = strings.TrimSpace(target.Endpoint)
	}
	if strings.TrimSpace(profile.TargetEndpoint) == "" {
		return nil, &modelsystem.ErrEndpointRequired
	}

	plan := &communicationif.OutboundPayloadPlan{
		RouteProfile: profile,
		Target:       target,
		PlainPayload: req.PlainPayload,
	}

	if req.EnsureChannel != nil && profile.SecurityPolicy == commonif.SecurityPolicyRequired {
		if req.AdditionalData == nil {
			req.AdditionalData = make(map[string]string)
		}
		req.AdditionalData["commsec_required"] = "true"
	}

	return plan, nil
}

func resolveRoutingSecurityPolicy(category commonif.FlowCategory) commonif.SecurityPolicy {
	switch category {
	case commonif.FlowCategoryBootstrapCall:
		return commonif.SecurityPolicyOptional
	case commonif.FlowCategoryBusinessForward,
		commonif.FlowCategoryExternalAuthRelay,
		commonif.FlowCategoryRemoteAuthVerify,
		commonif.FlowCategoryTargetReverify:
		return commonif.SecurityPolicyRequired
	default:
		return commonif.SecurityPolicyOptional
	}
}

func resolveRouteKeyCategory(routeKey string) (commonif.FlowCategory, bool) {
	switch strings.TrimSpace(strings.ToLower(routeKey)) {
	case bootstrapChallengeRouteKey, bootstrapAuthenticateRouteKey:
		return commonif.FlowCategoryBootstrapCall, true
	case remoteAuthVerifyRouteKey, remoteSessionValidateRouteKey:
		return commonif.FlowCategoryRemoteAuthVerify, true
	case externalAuthForwardRouteKey:
		return commonif.FlowCategoryExternalAuthRelay, true
	case businessForwardRouteKey:
		return commonif.FlowCategoryBusinessForward, true
	case targetReverifyRouteKey:
		return commonif.FlowCategoryTargetReverify, true
	}
	return "", false
}

func resolveStaticFlowCategory(flow *commonif.FlowRouteInput) (commonif.FlowCategory, bool) {
	if flow == nil {
		return "", false
	}
	if !strings.EqualFold(strings.TrimSpace(flow.Transport), "grpc") {
		return "", false
	}
	if !strings.EqualFold(strings.TrimSpace(flow.Method), "POST") {
		return "", false
	}
	switch strings.TrimSpace(strings.ToLower(flow.Path)) {
	case strings.ToLower(bootstrapInitMethodPath), strings.ToLower(bootstrapAuthMethodPath):
		return commonif.FlowCategoryBootstrapCall, true
	default:
		return "", false
	}
}
