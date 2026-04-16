package rpcservice_test

import (
	"context"
	"testing"

	authcontroliface "certification_server/src/iface/authcontrol"
	communicationif "certification_server/src/iface/communication"
	authmodel "certification_server/src/models/auth"
	communicationsvc "certification_server/src/services/communication"
)

type stubRoutingPipeline struct {
	profile *communicationif.RouteProfile
	plan    *communicationif.InboundPolicyPlan
}

func (s *stubRoutingPipeline) ResolveRouteProfile(ctx context.Context, input *communicationif.RoutingInput) (*communicationif.RouteProfile, error) {
	return s.profile, nil
}

func (s *stubRoutingPipeline) ClassifyFlow(ctx context.Context, input *communicationif.RoutingInput) (communicationif.FlowCategory, error) {
	if s.profile == nil {
		return "", nil
	}
	return s.profile.FlowCategory, nil
}

func (s *stubRoutingPipeline) BuildInboundPolicy(ctx context.Context, input *communicationif.RoutingInput) (*communicationif.InboundPolicyPlan, error) {
	return s.plan, nil
}

type stubInboundAuthControl struct {
	lastReq *authcontroliface.InboundControlRequest
	result  *authcontroliface.InboundControlResult
	err     error
}

func (s *stubInboundAuthControl) EnforceInbound(ctx context.Context, req *authcontroliface.InboundControlRequest) (*authcontroliface.InboundControlResult, error) {
	s.lastReq = req
	return s.result, s.err
}

func TestTrafficStationServiceDelegatesToAuthControl(t *testing.T) {
	routing := &stubRoutingPipeline{
		profile: &communicationif.RouteProfile{
			TargetServiceType: "service",
			TargetServiceName: "certification_server",
			TargetEndpoint:    "/bootstrap/challenge",
			FlowCategory:      communicationif.FlowCategoryBootstrapCall,
			SecurityPolicy:    communicationif.SecurityPolicyRequired,
			Operation:         "bootstrap.challenge",
			Metadata:          map[string]string{"route_owner": "auth"},
		},
		plan: &communicationif.InboundPolicyPlan{
			RouteProfile: &communicationif.RouteProfile{
				TargetServiceType: "service",
				TargetServiceName: "certification_server",
				TargetEndpoint:    "/bootstrap/challenge",
				FlowCategory:      communicationif.FlowCategoryBootstrapCall,
				SecurityPolicy:    communicationif.SecurityPolicyRequired,
				Operation:         "bootstrap.challenge",
				Metadata:          map[string]string{"route_owner": "auth"},
			},
			RequiredScopes: []string{"bootstrap:read"},
			Tags:           map[string]string{"env": "test"},
		},
	}
	authControl := &stubInboundAuthControl{
		result: &authcontroliface.InboundControlResult{
			RateLimitDecision: &authmodel.RateLimitDecision{
				Allowed:        false,
				ViolatedRuleID: "local-auth-control",
				RetryAfterSec:  12,
				Remaining:      0,
				SubjectKey:     "gateway-1|bootstrap.challenge",
				Reason:         "rate limited by local rule local-auth-control",
			},
		},
	}

	svc := communicationsvc.NewTrafficStationService(routing, authControl)
	decision, err := svc.HandleInbound(context.Background(), &communicationif.InboundTrafficRequest{
		Route: &communicationif.RoutingInput{
			RouteKey:      "bootstrap.challenge",
			Transport:     "grpc",
			Method:        "POST",
			SourceService: "gateway",
			TargetService: "certification_server",
		},
		Headers: map[string]string{
			"x-gateway-id": "gateway-1",
			"x-client-id":  "client-1",
			"x-source-ip":  "127.0.0.1",
		},
		Payload: "payload",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision == nil {
		t.Fatalf("expected traffic decision")
	}
	if decision.Accepted {
		t.Fatalf("expected authcontrol denial to propagate")
	}
	if decision.Reason != "rate limited by local rule local-auth-control" {
		t.Fatalf("expected denial reason to be preserved, got %q", decision.Reason)
	}
	if decision.Metadata["rate_limit_allowed"] != "false" {
		t.Fatalf("expected rate limit metadata to be present, got %#v", decision.Metadata)
	}
	if authControl.lastReq == nil || authControl.lastReq.RateLimitInput == nil {
		t.Fatalf("expected authcontrol to receive a rate limit input")
	}
	if authControl.lastReq.RateLimitInput.Module != "certification_server" {
		t.Fatalf("expected module to be forwarded, got %q", authControl.lastReq.RateLimitInput.Module)
	}
	if authControl.lastReq.RateLimitInput.Action != "bootstrap.challenge" {
		t.Fatalf("expected action to be forwarded, got %q", authControl.lastReq.RateLimitInput.Action)
	}
	if authControl.lastReq.RateLimitInput.Headers["x-gateway-id"] != "gateway-1" {
		t.Fatalf("expected headers to be forwarded, got %#v", authControl.lastReq.RateLimitInput.Headers)
	}
	if authControl.lastReq.RateLimitInput.Tags["env"] != "test" {
		t.Fatalf("expected tags to be forwarded, got %#v", authControl.lastReq.RateLimitInput.Tags)
	}
}

func TestTrafficStationServiceAllowsWithoutAuthControl(t *testing.T) {
	routing := &stubRoutingPipeline{
		plan: &communicationif.InboundPolicyPlan{
			RouteProfile: &communicationif.RouteProfile{
				TargetServiceType: "service",
				TargetServiceName: "certification_server",
				TargetEndpoint:    "/bootstrap/challenge",
				FlowCategory:      communicationif.FlowCategoryBootstrapCall,
				SecurityPolicy:    communicationif.SecurityPolicyRequired,
				Operation:         "bootstrap.challenge",
			},
		},
	}

	svc := communicationsvc.NewTrafficStationService(routing, nil)
	decision, err := svc.HandleInbound(context.Background(), &communicationif.InboundTrafficRequest{
		Route: &communicationif.RoutingInput{
			RouteKey:      "bootstrap.challenge",
			Transport:     "grpc",
			Method:        "POST",
			SourceService: "gateway",
			TargetService: "certification_server",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision == nil || !decision.Accepted {
		t.Fatalf("expected traffic decision to be accepted without authcontrol")
	}
	if decision.Reason != "accepted" {
		t.Fatalf("expected accepted reason, got %q", decision.Reason)
	}
}
