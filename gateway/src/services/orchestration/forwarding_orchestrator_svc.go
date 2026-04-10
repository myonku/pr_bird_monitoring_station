package orchestration

import (
	"context"

	communicationif "gateway/src/iface/communication"
	iface "gateway/src/iface/orchestration"
	modelsystem "gateway/src/models/system"
)

var _ iface.IForwardingOrchestrator = (*ForwardingOrchestratorService)(nil)

// ForwardingOrchestratorService 是网关转发编排的最小实现骨架。
type ForwardingOrchestratorService struct {
	trafficStation communicationif.ITrafficStation
}

func NewForwardingOrchestratorServiceWithDeps(
	trafficStation communicationif.ITrafficStation,
) *ForwardingOrchestratorService {
	return &ForwardingOrchestratorService{trafficStation: trafficStation}
}

// HandleBusinessForward 处理业务转发骨架逻辑。
func (s *ForwardingOrchestratorService) HandleBusinessForward(
	ctx context.Context, req *iface.ForwardingRequest,
) (*iface.ForwardingResult, error) {
	if req == nil {
		return nil, &modelsystem.ErrForwardingRequestInvalid
	}
	return s.handleForward(ctx, req)
}

// HandleExternalAuthForward 处理外部认证转发骨架逻辑。
func (s *ForwardingOrchestratorService) HandleExternalAuthForward(
	ctx context.Context, req *iface.ForwardingRequest,
) (*iface.ForwardingResult, error) {
	if req == nil {
		return nil, &modelsystem.ErrForwardingRequestInvalid
	}
	return s.handleForward(ctx, req)
}

func (s *ForwardingOrchestratorService) handleForward(
	ctx context.Context,
	req *iface.ForwardingRequest,
) (*iface.ForwardingResult, error) {
	if s.trafficStation == nil {
		return nil, &modelsystem.ErrForwardingDependenciesRequired
	}

	inboundDecision, err := s.trafficStation.HandleInbound(
		ctx,
		&communicationif.InboundTrafficRequest{
			Flow:    req.Flow,
			Headers: cloneStringMap(req.InboundHeaders),
			Payload: req.Payload,
		},
	)
	if err != nil {
		return nil, err
	}
	if inboundDecision == nil || !inboundDecision.Accepted {
		return nil, &modelsystem.ErrForwardingRequestInvalid
	}

	dispatch, err := s.trafficStation.SendOutbound(
		ctx,
		&communicationif.OutboundTrafficRequest{
			Flow:    req.Flow,
			Headers: cloneStringMap(req.InboundHeaders),
			Payload: req.Payload,
		},
	)
	if err != nil {
		return nil, err
	}
	if dispatch == nil || dispatch.Profile == nil {
		return nil, &modelsystem.ErrForwardingRequestInvalid
	}

	result := &iface.ForwardingResult{
		RouteProfile:   dispatch.Profile,
		TargetEndpoint: dispatch.TargetEndpoint,
		OutboundHeaders: map[string]string{
			"x-flow-category": string(dispatch.Profile.FlowCategory),
		},
		OutboundPayload: dispatch.Payload,
	}
	return result, nil
}

func cloneStringMap(source map[string]string) map[string]string {
	if len(source) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(source))
	for key, value := range source {
		out[key] = value
	}
	return out
}
