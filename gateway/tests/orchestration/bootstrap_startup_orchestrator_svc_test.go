package orchestration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	authmodel "gateway/src/models/auth"
	commsecmodel "gateway/src/models/commsec"
	orchestration "gateway/src/services/orchestration"
	"gateway/src/utils"

	"github.com/google/uuid"
)

type stubBootstrapKeyManager struct {
	public  commsecmodel.ServicePublicKeyRecord
	private commsecmodel.LocalPrivateKeyRef
}

func (s *stubBootstrapKeyManager) GetPublicKey(ctx context.Context) (commsecmodel.ServicePublicKeyRecord, error) {
	_ = ctx
	return s.public, nil
}

func (s *stubBootstrapKeyManager) GetPrivateKeyRef(ctx context.Context) (commsecmodel.LocalPrivateKeyRef, error) {
	_ = ctx
	return s.private, nil
}

func (s *stubBootstrapKeyManager) LookupPublicKey(ctx context.Context, req *commsecmodel.PublicKeyLookupRequest) (commsecmodel.PublicKeyLookupResult, error) {
	_ = ctx
	_ = req
	return commsecmodel.PublicKeyLookupResult{}, nil
}

func TestBuildChallengeSignerUsesRealSignatureAndExpectedPayload(t *testing.T) {
	publicPEM, privatePEM, err := generateEd25519KeyPairPEM()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	orchestrator := &orchestration.BootstrapStartupOrchestratorService{
		KeyManager: &stubBootstrapKeyManager{
			public: commsecmodel.ServicePublicKeyRecord{
				KeyID:        "gateway-local-key",
				PublicKeyPEM: string(publicPEM),
				Status:       commsecmodel.CommKeyActive,
			},
			private: commsecmodel.LocalPrivateKeyRef{
				KeyID:         "gateway-local-key",
				PrivateKeyRef: string(privatePEM),
			},
		},
	}

	signer, err := orchestrator.BuildChallengeSigner(context.Background())
	if err != nil {
		t.Fatalf("BuildChallengeSigner returned error: %v", err)
	}

	challenge := &authmodel.ChallengePayload{
		ChallengeID: uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		Issuer:      "certification_server",
		Audience:    "gateway",
		EntityType:  authmodel.EntityService,
		EntityID:    "gateway",
		KeyID:       "gateway-local-key",
		Nonce:       "nonce-123",
		IssuedAt:    time.Date(2026, 4, 22, 10, 0, 0, 0, time.UTC),
		ExpiresAt:   time.Date(2026, 4, 22, 10, 1, 0, 0, time.UTC),
	}

	signed, err := signer(context.Background(), challenge)
	if err != nil {
		t.Fatalf("signer returned error: %v", err)
	}
	if signed == nil {
		t.Fatal("expected signed challenge response")
	}
	if signed.KeyID != "gateway-local-key" {
		t.Fatalf("key id = %q, want %q", signed.KeyID, "gateway-local-key")
	}
	if signed.SignatureAlgorithm != commsecmodel.SignatureEd25519 {
		t.Fatalf("signature algorithm = %q, want %q", signed.SignatureAlgorithm, commsecmodel.SignatureEd25519)
	}

	payload, err := orchestration.BuildBootstrapSignaturePayload(challenge)
	if err != nil {
		t.Fatalf("buildBootstrapSignaturePayload returned error: %v", err)
	}
	const expectedPayload = "11111111-1111-1111-1111-111111111111|certification_server|gateway|service|gateway|gateway-local-key|nonce-123|2026-04-22T10:00:00Z|2026-04-22T10:01:00Z"
	if got := string(payload); got != expectedPayload {
		t.Fatalf("payload = %q, want %q", got, expectedPayload)
	}

	if err := (&utils.CryptoUtils{}).VerifyByAlgorithm("ed25519", payload, signed.Signature, publicPEM); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}
}

func generateEd25519KeyPairPEM() ([]byte, []byte, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)

	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, nil, err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	return publicPEM, privatePEM, nil
}
