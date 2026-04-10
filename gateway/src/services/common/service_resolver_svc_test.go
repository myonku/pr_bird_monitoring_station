package common

import (
	"context"
	"testing"

	commonif "gateway/src/iface/common"
)

func TestResolveRouteProfile_UsesFrozenBootstrapRouteKey(t *testing.T) {
	resolver := NewServiceResolverService(nil, nil, "")
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
	resolver := NewServiceResolverService(nil, nil, "")
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
