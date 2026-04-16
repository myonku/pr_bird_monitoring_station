package communication

import (
	"context"
	"strconv"
	"strings"

	authcontrolif "certification_server/src/iface/authcontrol"
	communicationif "certification_server/src/iface/communication"
	authmodel "certification_server/src/models/auth"
	modelsystem "certification_server/src/models/system"
)

var _ communicationif.ITrafficStation = (*TrafficStationService)(nil)

// TrafficStationService 提供认证中心统一入站流量站点实现。
type TrafficStationService struct {
	routingPipeline communicationif.IRoutingPayloadPipeline
	authControl     authcontrolif.IInboundAuthControl
}

func NewTrafficStationService(
	routingPipeline communicationif.IRoutingPayloadPipeline,
	authControl authcontrolif.IInboundAuthControl,
) communicationif.ITrafficStation {
	return &TrafficStationService{
		routingPipeline: routingPipeline,
		authControl:     authControl,
	}
}

func (s *TrafficStationService) HandleInbound(
	ctx context.Context,
	req *communicationif.InboundTrafficRequest,
) (*communicationif.TrafficDecision, error) {
	if req == nil || req.Route == nil {
		return nil, &modelsystem.ErrTrafficInboundRequestInvalid
	}
	if s.routingPipeline == nil {
		return nil, &modelsystem.ErrTrafficStationDependenciesRequired
	}

	policy, err := s.routingPipeline.BuildInboundPolicy(ctx, req.Route)
	if err != nil {
		return nil, err
	}
	if policy == nil || policy.RouteProfile == nil {
		return nil, &modelsystem.ErrRouteProfileNotFound
	}

	metadata := map[string]string{
		"flow_category":       string(policy.RouteProfile.FlowCategory),
		"security_policy":     string(policy.RouteProfile.SecurityPolicy),
		"operation":           strings.TrimSpace(policy.RouteProfile.Operation),
		"target_service_type": strings.TrimSpace(policy.RouteProfile.TargetServiceType),
		"target_service_name": strings.TrimSpace(policy.RouteProfile.TargetServiceName),
		"target_endpoint":     strings.TrimSpace(policy.RouteProfile.TargetEndpoint),
	}
	if len(policy.RequiredScopes) > 0 {
		metadata["required_scopes"] = strings.Join(policy.RequiredScopes, ",")
	}
	for key, value := range policy.Tags {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		metadata[key] = trimmed
	}

	decision := &communicationif.TrafficDecision{
		Accepted: true,
		Reason:   "accepted",
		Profile:  policy.RouteProfile,
		Metadata: metadata,
	}

	if s.authControl == nil {
		return decision, nil
	}

	controlResult, err := s.authControl.EnforceInbound(
		ctx,
		&authcontrolif.InboundControlRequest{
			RateLimitInput: buildInboundRateLimitInput(req, policy),
		},
	)
	if err != nil {
		return nil, err
	}
	if controlResult == nil || controlResult.RateLimitDecision == nil {
		return nil, &modelsystem.ErrRateLimitRequestInvalid
	}

	decision.Metadata["rate_limit_allowed"] = strconv.FormatBool(controlResult.RateLimitDecision.Allowed)
	decision.Metadata["rate_limit_rule_id"] = strings.TrimSpace(controlResult.RateLimitDecision.ViolatedRuleID)
	decision.Metadata["rate_limit_subject_key"] = strings.TrimSpace(controlResult.RateLimitDecision.SubjectKey)
	decision.Metadata["rate_limit_remaining"] = strconv.FormatInt(controlResult.RateLimitDecision.Remaining, 10)
	decision.Metadata["rate_limit_retry_after_sec"] = strconv.FormatInt(controlResult.RateLimitDecision.RetryAfterSec, 10)

	if !controlResult.RateLimitDecision.Allowed {
		decision.Accepted = false
		reason := strings.TrimSpace(controlResult.RateLimitDecision.Reason)
		if reason == "" {
			reason = "rate limited"
		}
		decision.Reason = reason
	}

	return decision, nil
}

func (s *TrafficStationService) SendOutbound(
	ctx context.Context,
	req *communicationif.OutboundTrafficRequest,
) (*communicationif.TrafficDispatchResult, error) {
	if req == nil || req.Route == nil {
		return nil, &modelsystem.ErrTrafficInboundRequestInvalid
	}
	if s.routingPipeline == nil {
		return nil, &modelsystem.ErrTrafficStationDependenciesRequired
	}

	profile, err := s.routingPipeline.ResolveRouteProfile(ctx, req.Route)
	if err != nil {
		return nil, err
	}
	if profile == nil {
		return nil, &modelsystem.ErrRouteProfileNotFound
	}

	return &communicationif.TrafficDispatchResult{
		Profile: profile,
		Payload: req.Payload,
		Metadata: map[string]string{
			"flow_category":       string(profile.FlowCategory),
			"security_policy":     string(profile.SecurityPolicy),
			"operation":           profile.Operation,
			"target_service_type": strings.TrimSpace(profile.TargetServiceType),
			"target_service_name": strings.TrimSpace(profile.TargetServiceName),
			"target_endpoint":     strings.TrimSpace(profile.TargetEndpoint),
		},
	}, nil
}

func buildInboundRateLimitInput(
	req *communicationif.InboundTrafficRequest,
	policy *communicationif.InboundPolicyPlan,
) *authcontrolif.InboundRateLimitInput {
	if req == nil || req.Route == nil || policy == nil || policy.RouteProfile == nil {
		return nil
	}

	headers := map[string]string{}
	for key, value := range req.Headers {
		trimmedKey := strings.ToLower(strings.TrimSpace(key))
		trimmedValue := strings.TrimSpace(value)
		if trimmedKey == "" || trimmedValue == "" {
			continue
		}
		headers[trimmedKey] = trimmedValue
	}

	tags := make(map[string]string, len(policy.Tags)+len(policy.RouteProfile.Metadata))
	for key, value := range policy.RouteProfile.Metadata {
		trimmedValue := strings.TrimSpace(value)
		if trimmedValue == "" {
			continue
		}
		tags[key] = trimmedValue
	}
	for key, value := range policy.Tags {
		trimmedValue := strings.TrimSpace(value)
		if trimmedValue == "" {
			continue
		}
		tags[key] = trimmedValue
	}
	for key, value := range headers {
		tags["header."+key] = value
	}

	return &authcontrolif.InboundRateLimitInput{
		Scope:         authmodel.RateLimitScopeAuth,
		Transport:     strings.TrimSpace(req.Route.Transport),
		Module:        strings.TrimSpace(policy.RouteProfile.TargetServiceName),
		Action:        strings.TrimSpace(policy.RouteProfile.Operation),
		Route:         strings.TrimSpace(req.Route.RouteKey),
		Method:        strings.TrimSpace(req.Route.Method),
		SourceIP:      headers["x-source-ip"],
		GatewayID:     firstNonEmpty(headers["x-gateway-id"], req.Route.SourceService),
		ClientID:      headers["x-client-id"],
		SourceService: strings.TrimSpace(req.Route.SourceService),
		TargetService: strings.TrimSpace(req.Route.TargetService),
		Headers:       headers,
		Tags:          tags,
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
