package outbound

import (
	"context"
	"errors"
	"testing"

	commif "gateway/src/interfaces/communication"
	authmodel "gateway/src/models/auth"
	modelsystem "gateway/src/models/system"

	"github.com/google/uuid"
	"google.golang.org/grpc/metadata"
)

type staticAssertionSigner struct {
	assertion string
	err       error
}

func (s *staticAssertionSigner) BuildAssertion(
	ctx context.Context,
	req *authmodel.InternalAssertionBuildRequest,
) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	return s.assertion, nil
}

func TestAttachSecurityMetadataSetsNormalizedDownstreamHeaders(t *testing.T) {
	forwarder := &GRPCOutboundForwarder{}
	grant := &authmodel.DownstreamAccessGrant{
		TokenID:     uuid.New(),
		SessionID:   uuid.New(),
		PrincipalID: "user:user-1",
	}

	ctx, err := forwarder.attachSecurityMetadata(
		context.Background(),
		&commif.OutboundForwardRequest{Headers: map[string]string{}},
		&commif.OutboundSecurityContext{Grant: grant},
	)
	if err != nil {
		t.Fatalf("attachSecurityMetadata returned error: %v", err)
	}

	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		t.Fatalf("missing outgoing metadata")
	}

	assertHeaderEquals(t, md, authmodel.HeaderDownstreamTokenID, grant.TokenID.String())
	assertHeaderEquals(t, md, authmodel.HeaderDownstreamSessionID, grant.SessionID.String())
	assertHeaderEquals(t, md, authmodel.HeaderDownstreamPrincipal, grant.PrincipalID)
}

func TestAttachSecurityMetadataInjectsInternalAssertion(t *testing.T) {
	forwarder := &GRPCOutboundForwarder{
		EnableInternalAssertion: true,
		InternalAssertionSigner: &staticAssertionSigner{assertion: "a.b.c"},
	}

	ctx, err := forwarder.attachSecurityMetadata(
		context.Background(),
		&commif.OutboundForwardRequest{
			TargetService: "api_service",
			Method:        "/api_service.v1.BirdService/Sync",
			Headers:       map[string]string{"x-request-id": "r-1"},
		},
		nil,
	)
	if err != nil {
		t.Fatalf("attachSecurityMetadata returned error: %v", err)
	}

	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		t.Fatalf("missing outgoing metadata")
	}
	assertHeaderEquals(t, md, authmodel.HeaderInternalAssertion, "a.b.c")
}

func TestAttachSecurityMetadataRequiresSignerWhenEnabled(t *testing.T) {
	forwarder := &GRPCOutboundForwarder{EnableInternalAssertion: true}
	_, err := forwarder.attachSecurityMetadata(
		context.Background(),
		&commif.OutboundForwardRequest{},
		nil,
	)
	if err == nil {
		t.Fatalf("expected error when signer is missing")
	}
	if !errors.Is(err, &modelsystem.ErrInternalAssertionSignerRequired) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func assertHeaderEquals(t *testing.T, md metadata.MD, key string, expected string) {
	t.Helper()
	values := md.Get(key)
	if len(values) == 0 {
		t.Fatalf("header %s not found", key)
	}
	if values[len(values)-1] != expected {
		t.Fatalf("header %s mismatch: got %s expected %s", key, values[len(values)-1], expected)
	}
}
