package common_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	commsecmodel "certification_server/src/models/commsec"
	modelsystem "certification_server/src/models/system"
	commonservice "certification_server/src/services/common"
)

func writeEd25519KeyPair(t *testing.T, dir string) ([]byte, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key pair: %v", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	if err := os.WriteFile(filepath.Join(dir, "public.pem"), publicPEM, 0o644); err != nil {
		t.Fatalf("write public pem: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "private.pem"), privatePEM, 0o600); err != nil {
		t.Fatalf("write private pem: %v", err)
	}
	return publicPEM, privatePEM
}

func TestSecretKeyServiceStartupAndLookup(t *testing.T) {
	dir := t.TempDir()
	writeEd25519KeyPair(t, dir)

	params := modelsystem.SecretKeyStartupParams{
		SecretKeyDir: dir,
		EntityType:   "service",
		EntityID:     "service-1",
		EntityName:   "certification_server",
		InstanceID:   "service-1",
		InstanceName: "certification_server",
	}
	svc, err := commonservice.NewSecretKeyServiceFromStartupParams(params, []commsecmodel.ServicePublicKeyRecord{{
		KeyID: "other-key",
		Owner: commsecmodel.ServiceKeyOwner{EntityType: "service", EntityID: "other-service"},
	}}, nil)
	if err != nil {
		t.Fatalf("unexpected service startup error: %v", err)
	}

	pub, err := svc.GetPublicKey(context.Background())
	if err != nil {
		t.Fatalf("unexpected get public key error: %v", err)
	}
	if pub.KeyID != "service-1" {
		t.Fatalf("expected fallback key id service-1, got %q", pub.KeyID)
	}

	priv, err := svc.GetPrivateKeyRef(context.Background())
	if err != nil {
		t.Fatalf("unexpected get private key error: %v", err)
	}
	if priv.KeyID != "service-1" {
		t.Fatalf("expected fallback private key id service-1, got %q", priv.KeyID)
	}

	byID, err := svc.GetPublicKeyByKeyID(context.Background(), "service-1")
	if err != nil || !byID.Found || byID.Key.KeyID != "service-1" {
		t.Fatalf("expected key lookup by id to succeed, got %+v err=%v", byID, err)
	}

	byEntity, err := svc.GetPublicKeyByEntityID(context.Background(), "service-1")
	if err != nil || !byEntity.Found || byEntity.Key.KeyID != "service-1" {
		t.Fatalf("expected key lookup by entity to succeed, got %+v err=%v", byEntity, err)
	}

	owner := commsecmodel.ServiceKeyOwner{EntityType: "service", EntityID: "service-1", EntityName: "certification_server", InstanceID: "service-1", InstanceName: "certification_server"}
	items, err := svc.GetPublicKeysByOwner(context.Background(), owner)
	if err != nil {
		t.Fatalf("unexpected owner lookup error: %v", err)
	}
	if len(items) == 0 {
		t.Fatalf("expected at least one key for owner")
	}

	lookup, err := svc.LookupPublicKey(context.Background(), &commsecmodel.PublicKeyLookupRequest{
		KeyID:         "service-1",
		RequireActive: true,
	})
	if err != nil || !lookup.Found || lookup.MatchedBy != "key_id" {
		t.Fatalf("expected lookup by key id to succeed, got %+v err=%v", lookup, err)
	}

	if _, err := svc.GetPublicKeyByKeyID(context.Background(), ""); err == nil {
		t.Fatalf("expected empty key id error")
	}
}

func TestSecretKeyFallbackAndMatching(t *testing.T) {
	owner := commsecmodel.ServiceKeyOwner{EntityType: "service", EntityID: "service-1", EntityName: "certification_server", InstanceID: "service-1", InstanceName: "certification_server"}
	key := commsecmodel.ServicePublicKeyRecord{KeyID: "service-1", Owner: owner, Status: commsecmodel.CommKeyActive, ActivatedAt: time.Now()}
	if !keyMatchesPublicLookup(t, key, commsecmodel.PublicKeyLookupRequest{KeyID: "service-1", RequireActive: true}) {
		t.Fatalf("expected key lookup to match")
	}
	_ = owner
	_ = key
}

func keyMatchesPublicLookup(t *testing.T, key commsecmodel.ServicePublicKeyRecord, query commsecmodel.PublicKeyLookupRequest) bool {
	t.Helper()
	result, err := commonservice.NewSecretKeyService(nil, key, commsecmodel.LocalPrivateKeyRef{}, nil).LookupPublicKey(context.Background(), &query)
	if err != nil {
		t.Fatalf("unexpected lookup error: %v", err)
	}
	return result.Found
}
