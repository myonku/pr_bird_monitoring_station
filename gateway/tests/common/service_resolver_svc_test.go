package common

import (
	"context"
	"testing"

	commonif "gateway/src/iface/common"
	commonsvc "gateway/src/services/common"
)

func TestResolveRouteProfile_UsesFrozenBootstrapRouteKey(t *testing.T) {
	resolver := commonsvc.NewServiceResolverService(nil, nil, "")
	flow := &commonif.FlowRouteInput{
		RouteKey:  "auth.bootstrap.authenticate",
		Transport: "grpc",
		Method:    "POST",
		Path:      "/bms.auth.v1.AuthAuthorityBootstrapService/AuthenticateBootstrap",
	}

	profile, err := resolver.ResolveRouteProfile(context.Background(), flow)
	if err != nil {
		t.Fatalf("ResolveRouteProfile returned error: %v", err)
	}
	if profile.FlowCategory != commonif.FlowCategoryBootstrapCall {
		t.Fatalf("unexpected flow category: %s", profile.FlowCategory)
	}
	if profile.TargetServiceName != "certification_server" {
		t.Fatalf("unexpected target service: %s", profile.TargetServiceName)
	}
	if profile.TargetServiceType != commonif.TargetServiceTypeAuthAuthority {
		t.Fatalf("unexpected target service type: %s", profile.TargetServiceType)
	}
}

func TestResolveRouteProfile_RejectsUntrustedBusinessHint(t *testing.T) {
	resolver := commonsvc.NewServiceResolverService(nil, nil, "")
	flow := &commonif.FlowRouteInput{
		RouteKey:          "business.forward.generic",
		Transport:         "grpc",
		Method:            "POST",
		Path:              "/example.Service/DoWork",
		TargetServiceHint: "malicious-service",
	}

	profile, err := resolver.ResolveRouteProfile(context.Background(), flow)
	if err == nil {
		t.Fatalf("expected error, got profile: %+v", profile)
	}
}

func TestResolveRouteProfile_ResolvesClientAndEdgeBusinessTargets(t *testing.T) {
	resolver := commonsvc.NewServiceResolverService(nil, nil, "")

	tests := []struct {
		name           string
		path           string
		expectedTarget string
	}{
		{
			name:           "client business",
			path:           "/v1/client/home/summary",
			expectedTarget: "data_server",
		},
		{
			name:           "edge business",
			path:           "/v1/edge/events",
			expectedTarget: "data_worker",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			profile, err := resolver.ResolveRouteProfile(context.Background(), &commonif.FlowRouteInput{
				RouteKey:  "business.forward.generic",
				Transport: "http",
				Method:    "POST",
				Path:      testCase.path,
			})
			if err != nil {
				t.Fatalf("ResolveRouteProfile returned error: %v", err)
			}
			if profile.TargetServiceName != testCase.expectedTarget {
				t.Fatalf("unexpected target service: %s", profile.TargetServiceName)
			}
			if profile.FlowCategory != commonif.FlowCategoryBusinessForward {
				t.Fatalf("unexpected flow category: %s", profile.FlowCategory)
			}
		})
	}
}
