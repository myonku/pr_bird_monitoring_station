package communication

import (
	"context"
	"testing"

	commonif "gateway/src/iface/common"
)

func TestClassifyFlow_AcceptsFrozenBootstrapRouteKey(t *testing.T) {
	pipeline := &RoutingPayloadPipelineService{}
	flow := &commonif.FlowRouteInput{
		RouteKey:  "auth.bootstrap.challenge",
		Transport: "grpc",
		Method:    "POST",
		Path:      "/bms.auth.v1.AuthAuthorityBootstrapService/InitBootstrapChallenge",
	}

	category, err := pipeline.ClassifyFlow(context.Background(), flow)
	if err != nil {
		t.Fatalf("ClassifyFlow returned error: %v", err)
	}
	if category != commonif.FlowCategoryBootstrapCall {
		t.Fatalf("unexpected category: %s", category)
	}
}

func TestClassifyFlow_RejectsUnknownRoute(t *testing.T) {
	pipeline := &RoutingPayloadPipelineService{}
	flow := &commonif.FlowRouteInput{
		RouteKey:  "unknown.route.key",
		Transport: "grpc",
		Method:    "POST",
		Path:      "/example.Service/Unknown",
	}

	if category, err := pipeline.ClassifyFlow(context.Background(), flow); err == nil {
		t.Fatalf("expected error, got category: %s", category)
	}
}
