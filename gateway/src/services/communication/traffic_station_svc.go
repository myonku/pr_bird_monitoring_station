package communication

import (
	"context"
	"strings"

	communicationif "gateway/src/iface/communication"
	modelsystem "gateway/src/models/system"
)

var _ communicationif.ITrafficStation = (*TrafficStationService)(nil)

// TrafficStationService 提供网关统一流量站点最小实现。
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

	payload := plan.PlainPayload
	if plan.Encrypted != nil {
		payload = plan.Encrypted.CipherText
	}

	dispatch := &communicationif.TrafficDispatchResult{
		Profile:        plan.RouteProfile,
		TargetEndpoint: plan.RouteProfile.TargetEndpoint,
		Payload:        payload,
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

	return dispatch, nil
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
