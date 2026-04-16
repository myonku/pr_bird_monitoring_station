package orchestration_test

import (
	"context"
	"testing"
	"time"

	authmodel "certification_server/src/models/auth"
	commonmodel "certification_server/src/models/common"
	commsecmodel "certification_server/src/models/commsec"
	modelsystem "certification_server/src/models/system"
	orchestration "certification_server/src/services/orchestration"
	"certification_server/src/utils"

	"github.com/google/uuid"
)

func TestHandleBootstrapChallengeStoresAndDefaults(t *testing.T) {
	orchestrator := orchestration.NewAuthRequestOrchestratorService()

	challenge, err := orchestrator.HandleBootstrapChallenge(context.Background(), &authmodel.ChallengeRequest{
		EntityType: commonmodel.EntityService,
		EntityID:   "certification-server",
		KeyID:      "service-key-1",
	})
	if err != nil {
		t.Fatalf("HandleBootstrapChallenge returned error: %v", err)
	}
	if challenge == nil {
		t.Fatal("HandleBootstrapChallenge returned nil challenge")
	}
	if challenge.ChallengeID == uuid.Nil {
		t.Fatal("challenge id must not be nil")
	}
	if challenge.Issuer != "certification_server" {
		t.Fatalf("unexpected issuer: %s", challenge.Issuer)
	}
	if challenge.Audience != "certification_server" {
		t.Fatalf("unexpected audience: %s", challenge.Audience)
	}
	if challenge.EntityType != commonmodel.EntityService {
		t.Fatalf("unexpected entity type: %s", challenge.EntityType)
	}
	if challenge.EntityID != "certification-server" {
		t.Fatalf("unexpected entity id: %s", challenge.EntityID)
	}
	if challenge.KeyID != "service-key-1" {
		t.Fatalf("unexpected key id: %s", challenge.KeyID)
	}
	if challenge.ExpiresAt.Sub(challenge.IssuedAt) != time.Minute {
		t.Fatalf("unexpected ttl: %s", challenge.ExpiresAt.Sub(challenge.IssuedAt))
	}

	payload, err := buildBootstrapSignaturePayload(challenge)
	if err != nil {
		t.Fatalf("buildBootstrapSignaturePayload returned error: %v", err)
	}
	if len(payload) == 0 {
		t.Fatal("expected bootstrap payload")
	}
}

func TestHandleBootstrapAuthenticateSuccessAndConsume(t *testing.T) {
	ctx := context.Background()
	pubPEM, privPEM := writeEd25519KeyMaterial(t)

	entityID := "certification-server"
	keyID := "service-key-1"
	familyID := uuid.New()
	accessTokenID := uuid.New()
	issuedAt := time.Date(2026, 4, 16, 12, 0, 0, 0, time.UTC)

	keyManager := &stubKeyManager{
		lookupResult: commsecmodel.PublicKeyLookupResult{
			Found: true,
			Key: commsecmodel.ServicePublicKeyRecord{
				KeyID: keyID,
				Owner: commsecmodel.ServiceKeyOwner{
					EntityType: string(commonmodel.EntityService),
					EntityID:   entityID,
				},
				PublicKeyPEM: pubPEM,
				Status:       commsecmodel.CommKeyActive,
			},
		},
	}
	sessionManager := &stubSessionManager{
		session: &authmodel.Session{
			ID:            uuid.New(),
			Principal:     authmodel.Principal{EntityType: commonmodel.EntityService, EntityID: entityID},
			EntityType:    commonmodel.EntityService,
			EntityID:      entityID,
			PrincipalID:   authmodel.Principal{EntityType: commonmodel.EntityService, EntityID: entityID}.PrincipalID(),
			Status:        authmodel.SessionActive,
			TokenFamilyID: familyID,
			CreatedAt:     issuedAt,
			ExpiresAt:     issuedAt.Add(15 * time.Minute),
		},
	}
	tokenManager := &stubTokenManager{
		bundle: &authmodel.TokenBundle{
			AccessToken: &authmodel.IssuedToken{
				Raw:    "access-token",
				Type:   authmodel.TokenAccess,
				TTLSec: 900,
				Claims: authmodel.TokenClaims{
					TokenID:   accessTokenID,
					FamilyID:  familyID,
					IssuedAt:  issuedAt,
					ExpiresAt: issuedAt.Add(15 * time.Minute),
				},
			},
			RefreshToken: &authmodel.IssuedToken{
				Raw:    "refresh-token",
				Type:   authmodel.TokenRefresh,
				TTLSec: 3600,
			},
		},
		issuedToken: &authmodel.IssuedToken{
			Raw:    "downstream-token",
			Type:   authmodel.TokenDownstream,
			TTLSec: 120,
		},
	}
	orchestrator := orchestration.NewAuthRequestOrchestratorServiceWithDeps(keyManager, sessionManager, tokenManager, nil)

	challenge, err := orchestrator.HandleBootstrapChallenge(ctx, defaultServiceChallengeRequest(entityID, keyID))
	if err != nil {
		t.Fatalf("HandleBootstrapChallenge returned error: %v", err)
	}

	payload, err := buildBootstrapSignaturePayload(challenge)
	if err != nil {
		t.Fatalf("buildBootstrapSignaturePayload returned error: %v", err)
	}
	signature, err := (&utils.CryptoUtils{}).SignByAlgorithm(string(commsecmodel.SignatureEd25519), payload, []byte(privPEM))
	if err != nil {
		t.Fatalf("SignByAlgorithm returned error: %v", err)
	}

	result, err := orchestrator.HandleBootstrapAuthenticate(ctx, &authmodel.BootstrapAuthRequest{
		Challenge: *challenge,
		Signed: authmodel.SignedChallengeResponse{
			ChallengeID:        challenge.ChallengeID,
			KeyID:              keyID,
			SignatureAlgorithm: commsecmodel.SignatureEd25519,
			Signature:          signature,
			SignedAt:           issuedAt.Add(5 * time.Second),
		},
		Scopes:                 []string{"service:read"},
		Role:                   "service",
		RequireDownstreamToken: true,
	})
	if err != nil {
		t.Fatalf("HandleBootstrapAuthenticate returned error: %v", err)
	}
	if result == nil {
		t.Fatal("HandleBootstrapAuthenticate returned nil result")
	}
	if result.Stage != authmodel.BootstrapStageReady {
		t.Fatalf("unexpected stage: %s", result.Stage)
	}
	if result.ActiveCommKeyID != keyID {
		t.Fatalf("unexpected active comm key id: %s", result.ActiveCommKeyID)
	}
	if result.Identity == nil {
		t.Fatal("identity must not be nil")
	}
	if result.Identity.PrincipalID != "service:"+entityID {
		t.Fatalf("unexpected principal id: %s", result.Identity.PrincipalID)
	}
	if result.Identity.TokenID != accessTokenID {
		t.Fatalf("unexpected token id: %s", result.Identity.TokenID)
	}
	if result.Identity.TokenFamilyID != familyID {
		t.Fatalf("unexpected token family id: %s", result.Identity.TokenFamilyID)
	}
	if result.Session == nil {
		t.Fatal("session must not be nil")
	}
	if result.Session.ID != sessionManager.session.ID {
		t.Fatalf("unexpected session id: %s", result.Session.ID)
	}
	if result.Tokens.AccessToken == nil || result.Tokens.RefreshToken == nil || result.Tokens.DownstreamToken == nil {
		t.Fatal("expected access, refresh and downstream tokens")
	}
	if tokenManager.issueBundleReq == nil {
		t.Fatal("expected issue token bundle request to be recorded")
	}
	if tokenManager.issueBundleReq.Audience != "internal" {
		t.Fatalf("unexpected issue bundle audience: %s", tokenManager.issueBundleReq.Audience)
	}
	if tokenManager.issueTokenReq == nil {
		t.Fatal("expected downstream issue request to be recorded")
	}
	if tokenManager.issueTokenReq.TokenType != authmodel.TokenDownstream {
		t.Fatalf("unexpected downstream token type: %s", tokenManager.issueTokenReq.TokenType)
	}
	if tokenManager.issueTokenReq.TTLSec != 120 {
		t.Fatalf("unexpected downstream token ttl: %d", tokenManager.issueTokenReq.TTLSec)
	}

	replayResult, err := orchestrator.HandleBootstrapAuthenticate(ctx, &authmodel.BootstrapAuthRequest{
		Challenge: *challenge,
		Signed: authmodel.SignedChallengeResponse{
			ChallengeID:        challenge.ChallengeID,
			KeyID:              keyID,
			SignatureAlgorithm: commsecmodel.SignatureEd25519,
			Signature:          signature,
		},
	})
	if err == nil {
		t.Fatalf("expected replay to fail, got %+v", replayResult)
	}
	if err.Error() != modelsystem.ErrChallengeNotFound.Error() {
		t.Fatalf("expected challenge consumed error, got %v", err)
	}
}

func TestHandleBootstrapAuthenticateRejectsBadSignature(t *testing.T) {
	ctx := context.Background()
	pubPEM, _ := writeEd25519KeyMaterial(t)
	_, wrongPrivPEM := writeEd25519KeyMaterial(t)

	entityID := "certification-server"
	keyID := "service-key-1"
	orchestrator := orchestration.NewAuthRequestOrchestratorServiceWithDeps(
		&stubKeyManager{
			lookupResult: commsecmodel.PublicKeyLookupResult{
				Found: true,
				Key: commsecmodel.ServicePublicKeyRecord{
					KeyID: keyID,
					Owner: commsecmodel.ServiceKeyOwner{
						EntityType: string(commonmodel.EntityService),
						EntityID:   entityID,
					},
					PublicKeyPEM: pubPEM,
					Status:       commsecmodel.CommKeyActive,
				},
			},
		},
		&stubSessionManager{},
		&stubTokenManager{},
		nil,
	)

	challenge, err := orchestrator.HandleBootstrapChallenge(ctx, defaultServiceChallengeRequest(entityID, keyID))
	if err != nil {
		t.Fatalf("HandleBootstrapChallenge returned error: %v", err)
	}

	payload, err := buildBootstrapSignaturePayload(challenge)
	if err != nil {
		t.Fatalf("buildBootstrapSignaturePayload returned error: %v", err)
	}
	wrongSignature, err := (&utils.CryptoUtils{}).SignByAlgorithm(string(commsecmodel.SignatureEd25519), payload, []byte(wrongPrivPEM))
	if err != nil {
		t.Fatalf("SignByAlgorithm returned error: %v", err)
	}

	_, err = orchestrator.HandleBootstrapAuthenticate(ctx, &authmodel.BootstrapAuthRequest{
		Challenge: *challenge,
		Signed: authmodel.SignedChallengeResponse{
			ChallengeID:        challenge.ChallengeID,
			KeyID:              keyID,
			SignatureAlgorithm: commsecmodel.SignatureEd25519,
			Signature:          wrongSignature,
		},
	})
	if err == nil {
		t.Fatal("expected signature verification error")
	}
	if err.Error() != modelsystem.ErrChallengeResponseMismatch.Error() {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = orchestrator.HandleBootstrapAuthenticate(ctx, &authmodel.BootstrapAuthRequest{
		Challenge: *challenge,
		Signed: authmodel.SignedChallengeResponse{
			ChallengeID:        challenge.ChallengeID,
			KeyID:              keyID,
			SignatureAlgorithm: commsecmodel.SignatureEd25519,
			Signature:          wrongSignature,
		},
	})
	if err == nil {
		t.Fatal("expected consumed challenge to fail")
	}
	if err.Error() != modelsystem.ErrChallengeNotFound.Error() {
		t.Fatalf("expected challenge consumed error, got %v", err)
	}
}
