package communication

import (
	"context"
	"testing"

	authcontrolif "gateway/src/iface/authcontrol"
	commonif "gateway/src/iface/common"
	communicationif "gateway/src/iface/communication"
	authmodel "gateway/src/models/auth"
	commonmodel "gateway/src/models/common"
	communication "gateway/src/services/communication"
)

type stubRoutingPipeline struct {
	profile      *commonif.RouteProfile
	outboundPlan *communicationif.OutboundPayloadPlan
}

func (s *stubRoutingPipeline) ResolveRouteProfile(ctx context.Context, flow *commonif.FlowRouteInput) (*commonif.RouteProfile, error) {
	_ = ctx
	_ = flow
	return s.profile, nil
}

func (s *stubRoutingPipeline) ClassifyFlow(ctx context.Context, flow *commonif.FlowRouteInput) (commonif.FlowCategory, error) {
	_ = ctx
	_ = flow
	if s.profile == nil {
		return commonif.FlowCategoryBusinessForward, nil
	}
	return s.profile.FlowCategory, nil
}

func (s *stubRoutingPipeline) BuildOutboundPayload(ctx context.Context, req *communicationif.BuildOutboundPayloadRequest) (*communicationif.OutboundPayloadPlan, error) {
	_ = ctx
	if s.outboundPlan != nil {
		return s.outboundPlan, nil
	}
	return &communicationif.OutboundPayloadPlan{
		RouteProfile: s.profile,
		PlainPayload: req.PlainPayload,
		Target: &commonmodel.ServiceInstance{
			Endpoint: "127.0.0.1:9001",
		},
	}, nil
}

type stubGatewayAuthControl struct {
	calls   int
	lastReq *authcontrolif.AuthControlRequest
	result  *authcontrolif.AuthControlResult
}

func (s *stubGatewayAuthControl) Enforce(ctx context.Context, req *authcontrolif.AuthControlRequest) (*authcontrolif.AuthControlResult, error) {
	_ = ctx
	s.calls++
	s.lastReq = req
	if s.result != nil {
		return s.result, nil
	}
	return &authcontrolif.AuthControlResult{
		RateLimitDecision: &authmodel.RateLimitDecision{Allowed: true, Remaining: 1, SubjectKey: "ok", Reason: "allowed"},
	}, nil
}

func TestTrafficStationServiceHandleInboundInvokesAuthControl(t *testing.T) {
	authControl := &stubGatewayAuthControl{}
	station := communication.NewTrafficStationService(
		&stubRoutingPipeline{
			profile: &commonif.RouteProfile{
				TargetServiceType: commonif.TargetServiceTypeInternal,
				TargetServiceName: "data_server",
				TargetEndpoint:    "127.0.0.1:9001",
				FlowCategory:      commonif.FlowCategoryBusinessForward,
				SecurityPolicy:    commonif.SecurityPolicyRequired,
			},
		},
		authControl,
	)

	decision, err := station.HandleInbound(context.Background(), &communicationif.InboundTrafficRequest{
		Flow: &commonif.FlowRouteInput{
			RouteKey:      "business.forward.generic",
			Transport:     "http",
			Method:        "POST",
			Path:          "/v1/business/forward",
			SourceService: "gateway",
		},
		Headers: map[string]string{
			"x-source-ip": "127.0.0.1",
		},
		Payload: "{}",
	})
	if err != nil {
		t.Fatalf("HandleInbound returned error: %v", err)
	}
	if authControl.calls != 1 {
		t.Fatalf("expected one authcontrol call, got %d", authControl.calls)
	}
	if authControl.lastReq == nil || authControl.lastReq.Purpose != authcontrolif.AuthControlPurposeInbound {
		t.Fatalf("expected inbound authcontrol request, got %#v", authControl.lastReq)
	}
	if authControl.lastReq.RateLimit == nil || authControl.lastReq.RateLimit.Scope != authmodel.RateLimitScopeAuth {
		t.Fatalf("expected inbound rate limit input, got %#v", authControl.lastReq.RateLimit)
	}
	if decision == nil || !decision.Accepted {
		t.Fatalf("expected accepted traffic decision, got %#v", decision)
	}
}

func TestTrafficStationServiceSendOutboundInvokesAuthControl(t *testing.T) {
	authControl := &stubGatewayAuthControl{}
	station := communication.NewTrafficStationService(
		&stubRoutingPipeline{
			profile: &commonif.RouteProfile{
				TargetServiceType: commonif.TargetServiceTypeInternal,
				TargetServiceName: "data_server",
				TargetEndpoint:    "127.0.0.1:9001",
				FlowCategory:      commonif.FlowCategoryBusinessForward,
				SecurityPolicy:    commonif.SecurityPolicyRequired,
			},
		},
		authControl,
	)

	dispatch, err := station.SendOutbound(context.Background(), &communicationif.OutboundTrafficRequest{
		Flow: &commonif.FlowRouteInput{
			RouteKey:      "business.forward.generic",
			Transport:     "grpc",
			Method:        "POST",
			Path:          "/bms.business.v1.BusinessForwardService/ForwardBusiness",
			SourceService: "gateway",
		},
		Headers: map[string]string{
			"x-source-ip": "127.0.0.1",
		},
		Payload: "payload",
	})
	if err != nil {
		t.Fatalf("SendOutbound returned error: %v", err)
	}
	if authControl.calls != 1 {
		t.Fatalf("expected one authcontrol call, got %d", authControl.calls)
	}
	if authControl.lastReq == nil || authControl.lastReq.Purpose != authcontrolif.AuthControlPurposeOutbound {
		t.Fatalf("expected outbound authcontrol request, got %#v", authControl.lastReq)
	}
	if authControl.lastReq.RateLimit == nil || authControl.lastReq.RateLimit.Scope != authmodel.RateLimitScopeInternalRPC {
		t.Fatalf("expected outbound rate limit input, got %#v", authControl.lastReq.RateLimit)
	}
	if dispatch == nil || dispatch.TargetEndpoint == "" {
		t.Fatalf("expected outbound dispatch to resolve endpoint, got %#v", dispatch)
	}
}
