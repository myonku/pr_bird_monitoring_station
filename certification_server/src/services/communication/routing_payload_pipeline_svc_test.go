package communication

import (
	"context"
	"testing"

	communicationif "certification_server/src/iface/communication"
)

func TestClassifyFlow_AcceptsFrozenBootstrapRouteKey(t *testing.T) {
	pipeline := &RoutingPayloadPipelineService{}
	input := &communicationif.RoutingInput{
		RouteKey:  "auth.bootstrap.authenticate",
		Transport: "grpc",
		Method:    "POST",
		Path:      "/bms.auth.v1.AuthAuthorityBootstrapService/AuthenticateBootstrap",
	}

	category, err := pipeline.ClassifyFlow(context.Background(), input)
	if err != nil {
		t.Fatalf("ClassifyFlow returned error: %v", err)
	}
	if category != communicationif.FlowCategoryBootstrapCall {
		t.Fatalf("unexpected category: %s", category)
	}
}

func TestClassifyFlow_RejectsUnknownRoute(t *testing.T) {
	pipeline := &RoutingPayloadPipelineService{}
	input := &communicationif.RoutingInput{
		RouteKey:  "unknown.route.key",
		Transport: "grpc",
		Method:    "POST",
		Path:      "/example.Service/Unknown",
	}

	if category, err := pipeline.ClassifyFlow(context.Background(), input); err == nil {
		t.Fatalf("expected error, got category: %s", category)
	}
}
