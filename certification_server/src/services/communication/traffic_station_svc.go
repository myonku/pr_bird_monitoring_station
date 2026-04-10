package communication

import (
	"context"
	"strings"

	communicationif "certification_server/src/iface/communication"
	modelsystem "certification_server/src/models/system"
)

var _ communicationif.ITrafficStation = (*TrafficStationService)(nil)

// TrafficStationService 提供认证中心统一入站流量站点实现。
type TrafficStationService struct {
	routingPipeline communicationif.IRoutingPayloadPipeline
}

func NewTrafficStationService(
	routingPipeline communicationif.IRoutingPayloadPipeline,
) communicationif.ITrafficStation {
	return &TrafficStationService{routingPipeline: routingPipeline}
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
	if policy.RequireSecureChannel {
		metadata["commsec_required"] = "true"
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
