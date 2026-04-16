package orchestration_test

import (
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	authmodel "certification_server/src/models/auth"
	commonmodel "certification_server/src/models/common"
)

func writeEd25519KeyMaterial(t *testing.T) (string, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey returned error: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey returned error: %v", err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	return string(pubPEM), string(privPEM)
}

func buildBootstrapSignaturePayload(challenge *authmodel.ChallengePayload) ([]byte, error) {
	if challenge == nil {
		return nil, nil
	}

	fields := []string{
		challenge.ChallengeID.String(),
		challenge.Issuer,
		challenge.Audience,
		string(challenge.EntityType),
		challenge.EntityID,
		challenge.KeyID,
		challenge.Nonce,
		challenge.IssuedAt.UTC().Format(time.RFC3339Nano),
		challenge.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}
	return []byte(strings.Join(fields, "|")), nil
}

func defaultServiceChallengeRequest(entityID, keyID string) *authmodel.ChallengeRequest {
	return &authmodel.ChallengeRequest{
		EntityType: commonmodel.EntityService,
		EntityID:   entityID,
		KeyID:      keyID,
		Audience:   "internal",
		TTLSec:     60,
	}
}
