package app

import (
	"context"
	"errors"
	"testing"

	outbound "gateway/src/adapters/outbound"
	authmodel "gateway/src/models/auth"
	commsecmodel "gateway/src/models/commsec"
	modelsystem "gateway/src/models/system"
	authsvc "gateway/src/services/auth"
)

type noopSecretKeyService struct{}

func (s *noopSecretKeyService) GetPublicKey(ctx context.Context) (commsecmodel.ServicePublicKeyRecord, error) {
	return commsecmodel.ServicePublicKeyRecord{}, nil
}

func (s *noopSecretKeyService) GetPrivateKeyRef(ctx context.Context) (commsecmodel.LocalPrivateKeyRef, error) {
	return commsecmodel.LocalPrivateKeyRef{}, nil
}

func (s *noopSecretKeyService) LookupPublicKey(ctx context.Context, req *commsecmodel.PublicKeyLookupRequest) (commsecmodel.PublicKeyLookupResult, error) {
	return commsecmodel.PublicKeyLookupResult{}, nil
}

func TestWireInternalAssertionDisabledByDefault(t *testing.T) {
	fwd := &outbound.GRPCOutboundForwarder{}

	err := WireInternalAssertion(fwd, nil, nil)
	if err != nil {
		t.Fatalf("WireInternalAssertion returned error: %v", err)
	}

	if fwd.EnableInternalAssertion {
		t.Fatalf("internal assertion should be disabled by default")
	}
	if fwd.InternalAssertionSigner != nil {
		t.Fatalf("signer should be nil when disabled")
	}
	if fwd.InternalAssertionHeader != authmodel.HeaderInternalAssertion {
		t.Fatalf("default header mismatch: got %s", fwd.InternalAssertionHeader)
	}
}

func TestWireInternalAssertionRequiresSecretKeyServiceWhenEnabled(t *testing.T) {
	fwd := &outbound.GRPCOutboundForwarder{}
	cfg := &modelsystem.ProjectConfig{
		InternalAssertion: &modelsystem.InternalAssertionConfig{Enabled: true},
	}

	err := WireInternalAssertion(fwd, nil, cfg)
	if err == nil {
		t.Fatalf("expected error when enabled but secret key service is nil")
	}
	if !errors.Is(err, &modelsystem.ErrInternalAssertionSignerRequired) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWireInternalAssertionAppliesConfigToSigner(t *testing.T) {
	fwd := &outbound.GRPCOutboundForwarder{}
	cfg := &modelsystem.ProjectConfig{
		InternalAssertion: &modelsystem.InternalAssertionConfig{
			Enabled:            true,
			HeaderName:         "x-assertion-int",
			TTLSeconds:         35,
			Issuer:             "gateway-main",
			SignatureAlgorithm: "Ed25519",
		},
	}

	err := WireInternalAssertion(fwd, &noopSecretKeyService{}, cfg)
	if err != nil {
		t.Fatalf("WireInternalAssertion returned error: %v", err)
	}

	if !fwd.EnableInternalAssertion {
		t.Fatalf("internal assertion should be enabled")
	}
	if fwd.InternalAssertionHeader != "x-assertion-int" {
		t.Fatalf("header mismatch: got %s", fwd.InternalAssertionHeader)
	}

	signer, ok := fwd.InternalAssertionSigner.(*authsvc.DefaultInternalAssertionSigner)
	if !ok {
		t.Fatalf("unexpected signer type: %T", fwd.InternalAssertionSigner)
	}
	if signer.DefaultTTLSeconds != 35 {
		t.Fatalf("ttl mismatch: got %d", signer.DefaultTTLSeconds)
	}
	if signer.Issuer != "gateway-main" {
		t.Fatalf("issuer mismatch: got %s", signer.Issuer)
	}
	if signer.DefaultSignatureAlgorithm != commsecmodel.SignatureEd25519 {
		t.Fatalf("signature algorithm mismatch: got %s", signer.DefaultSignatureAlgorithm)
	}
}
