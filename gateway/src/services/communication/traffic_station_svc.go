package communication

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	authcontrolif "gateway/src/iface/authcontrol"
	commonif "gateway/src/iface/common"
	communicationif "gateway/src/iface/communication"
	authmodel "gateway/src/models/auth"
	modelsystem "gateway/src/models/system"
)

var _ communicationif.ITrafficStation = (*TrafficStationService)(nil)

// TrafficStationService 提供网关统一流量站点最小实现。
type TrafficStationService struct {
	routingPipeline communicationif.IRoutingPayloadPipeline
	authControl     authcontrolif.IGatewayAuthControl
}

// NewTrafficStationService 构造流量站点，authControl 为可选依赖。
func NewTrafficStationService(
	routingPipeline communicationif.IRoutingPayloadPipeline,
	authControl ...authcontrolif.IGatewayAuthControl,
) communicationif.ITrafficStation {
	var resolvedAuthControl authcontrolif.IGatewayAuthControl
	if len(authControl) > 0 {
		resolvedAuthControl = authControl[0]
	}

	return &TrafficStationService{
		routingPipeline: routingPipeline,
		authControl:     resolvedAuthControl,
	}
}

func (s *TrafficStationService) HandleInbound(
	ctx context.Context,
	req *communicationif.InboundTrafficRequest,
) (*communicationif.TrafficDecision, error) {
	if req == nil || req.Flow == nil {
		return nil, &modelsystem.ErrForwardingRequestInvalid
	}
	if s.routingPipeline == nil {
		return nil, &modelsystem.ErrForwardingDependenciesRequired
	}

	profile, err := s.routingPipeline.ResolveRouteProfile(ctx, req.Flow)
	if err != nil {
		return nil, err
	}

	decision := &communicationif.TrafficDecision{
		Accepted: true,
		Reason:   "accepted",
		Profile:  profile,
		Metadata: map[string]string{
			"flow_category":   string(profile.FlowCategory),
			"security_policy": string(profile.SecurityPolicy),
			"target_service":  profile.TargetServiceName,
			"target_endpoint": profile.TargetEndpoint,
		},
	}

	if strings.TrimSpace(profile.TargetServiceName) == "" {
		decision.Accepted = false
		decision.Reason = "route_target_unresolved"
		return decision, nil
	}

	if s.authControl == nil {
		return decision, nil
	}

	authResult, err := s.authControl.Enforce(
		ctx,
		&authcontrolif.AuthControlRequest{
			Purpose:   authcontrolif.AuthControlPurposeInbound,
			RateLimit: buildTrafficRateLimitInput(req.Flow, profile, req.Headers, authmodel.RateLimitScopeAuth),
		},
	)
	if err != nil {
		return nil, err
	}
	if authResult == nil || authResult.RateLimitDecision == nil {
		return nil, &modelsystem.ErrRateLimitRequestInvalid
	}

	decision.Metadata["auth_control_allowed"] = strconv.FormatBool(authResult.RateLimitDecision.Allowed)
	decision.Metadata["auth_control_subject_key"] = strings.TrimSpace(authResult.RateLimitDecision.SubjectKey)
	decision.Metadata["auth_control_remaining"] = strconv.FormatInt(authResult.RateLimitDecision.Remaining, 10)
	decision.Metadata["auth_control_retry_after_sec"] = strconv.FormatInt(authResult.RateLimitDecision.RetryAfterSec, 10)
	if reason := strings.TrimSpace(authResult.RateLimitDecision.Reason); reason != "" {
		decision.Metadata["auth_control_reason"] = reason
	}
	if authResult.Identity != nil && strings.TrimSpace(authResult.Identity.PrincipalID) != "" {
		decision.Metadata["auth_control_principal_id"] = strings.TrimSpace(authResult.Identity.PrincipalID)
	}
	if authResult.Session != nil {
		decision.Metadata["auth_control_session_status"] = string(authResult.Session.Status)
	}
	if authResult.TokenVerification != nil {
		decision.Metadata["auth_control_token_valid"] = strconv.FormatBool(authResult.TokenVerification.Valid)
	}

	if !authResult.RateLimitDecision.Allowed {
		decision.Accepted = false
		reason := strings.TrimSpace(authResult.RateLimitDecision.Reason)
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
	if req == nil || req.Flow == nil {
		return nil, &modelsystem.ErrForwardingRequestInvalid
	}
	if s.routingPipeline == nil {
		return nil, &modelsystem.ErrForwardingDependenciesRequired
	}

	profile, err := s.routingPipeline.ResolveRouteProfile(ctx, req.Flow)
	if err != nil {
		return nil, err
	}
	if profile == nil {
		return nil, &modelsystem.ErrRouteRuleNotFound
	}

	if s.authControl != nil {
		authResult, err := s.authControl.Enforce(
			ctx,
			&authcontrolif.AuthControlRequest{
				Purpose: authcontrolif.AuthControlPurposeOutbound,
				RateLimit: buildTrafficRateLimitInput(
					req.Flow,
					profile,
					req.Headers,
					authmodel.RateLimitScopeInternalRPC,
				),
			},
		)
		if err != nil {
			return nil, err
		}
		if authResult == nil || authResult.RateLimitDecision == nil {
			return nil, &modelsystem.ErrRateLimitRequestInvalid
		}
		if !authResult.RateLimitDecision.Allowed {
			reason := strings.TrimSpace(authResult.RateLimitDecision.Reason)
			if reason == "" {
				reason = "rate limited"
			}
			return nil, fmt.Errorf("%w: %s", &modelsystem.ErrRequestRateLimited, reason)
		}
	}

	plan, err := s.routingPipeline.BuildOutboundPayload(
		ctx,
		&communicationif.BuildOutboundPayloadRequest{
			Flow:           req.Flow,
			PlainPayload:   req.Payload,
			AdditionalData: copyMetadata(req.Headers),
		},
	)
	if err != nil {
		return nil, err
	}

	dispatch := &communicationif.TrafficDispatchResult{
		Profile:        plan.RouteProfile,
		TargetEndpoint: plan.RouteProfile.TargetEndpoint,
		Payload:        plan.PlainPayload,
		Metadata: map[string]string{
			"flow_category":   string(plan.RouteProfile.FlowCategory),
			"security_policy": string(plan.RouteProfile.SecurityPolicy),
			"target_service":  plan.RouteProfile.TargetServiceName,
			"target_endpoint": plan.RouteProfile.TargetEndpoint,
		},
	}
	if plan.Target != nil && strings.TrimSpace(dispatch.TargetEndpoint) == "" {
		dispatch.TargetEndpoint = strings.TrimSpace(plan.Target.Endpoint)
		dispatch.Metadata["target_endpoint"] = dispatch.TargetEndpoint
	}

	if s.authControl != nil {
		dispatch.Metadata["auth_control_allowed"] = "true"
	}

	return dispatch, nil
}

func buildTrafficRateLimitInput(
	flow *commonif.FlowRouteInput,
	profile *commonif.RouteProfile,
	headers map[string]string,
	scope authmodel.RateLimitScope,
) *authcontrolif.RateLimitInput {
	if flow == nil || profile == nil {
		return nil
	}

	normalizedHeaders := normalizeStringMap(headers)
	tags := map[string]string{
		"route_key":       strings.TrimSpace(flow.RouteKey),
		"flow_category":   string(profile.FlowCategory),
		"security_policy": string(profile.SecurityPolicy),
		"target_service":  strings.TrimSpace(profile.TargetServiceName),
		"target_endpoint": strings.TrimSpace(profile.TargetEndpoint),
		"source_service":  strings.TrimSpace(flow.SourceService),
		"transport":       strings.TrimSpace(flow.Transport),
		"method":          strings.TrimSpace(flow.Method),
	}
	for key, value := range flow.Metadata {
		trimmedKey := strings.TrimSpace(key)
		trimmedValue := strings.TrimSpace(value)
		if trimmedKey == "" || trimmedValue == "" {
			continue
		}
		tags[trimmedKey] = trimmedValue
	}
	for key, value := range normalizedHeaders {
		tags["header."+key] = value
	}

	action := strings.TrimSpace(flow.Path)
	if action == "" {
		action = strings.TrimSpace(flow.RouteKey)
	}

	return &authcontrolif.RateLimitInput{
		Scope:         scope,
		Transport:     strings.TrimSpace(flow.Transport),
		Module:        strings.TrimSpace(profile.TargetServiceName),
		Action:        action,
		Route:         strings.TrimSpace(flow.RouteKey),
		Method:        strings.TrimSpace(flow.Method),
		SourceIP:      firstNonEmpty(normalizedHeaders["x-source-ip"], normalizedHeaders["x-real-ip"]),
		GatewayID:     firstNonEmpty(normalizedHeaders["x-gateway-id"], flow.SourceService),
		ClientID:      normalizedHeaders["x-client-id"],
		SourceService: strings.TrimSpace(flow.SourceService),
		TargetService: strings.TrimSpace(profile.TargetServiceName),
		Headers:       normalizedHeaders,
		Tags:          tags,
	}
}

func normalizeStringMap(source map[string]string) map[string]string {
	if len(source) == 0 {
		return map[string]string{}
	}

	out := make(map[string]string, len(source))
	for key, value := range source {
		trimmedKey := strings.ToLower(strings.TrimSpace(key))
		trimmedValue := strings.TrimSpace(value)
		if trimmedKey == "" || trimmedValue == "" {
			continue
		}
		out[trimmedKey] = trimmedValue
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func copyMetadata(source map[string]string) map[string]string {
	if len(source) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(source))
	for key, value := range source {
		out[key] = value
	}
	return out
}
