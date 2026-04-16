package orchestration_test

import (
	"context"
	"testing"

	commonif "certification_server/src/iface/common"
	orchestrationif "certification_server/src/iface/orchestration"
	authmodel "certification_server/src/models/auth"
	commonmodel "certification_server/src/models/common"
	commsecmodel "certification_server/src/models/commsec"
	modelsystem "certification_server/src/models/system"
	commonservice "certification_server/src/services/common"
	orchestration "certification_server/src/services/orchestration"
	"certification_server/src/utils"

	"github.com/google/uuid"
)

type fakeCredentialManager struct {
	result *commonif.UserCredentialValidationResult
	err    error
}

func (f *fakeCredentialManager) ValidateCredentials(ctx context.Context, req commonif.UserPwdCredentialRequest) (*commonif.UserCredentialValidationResult, error) {
	_ = ctx
	if f.err != nil {
		return nil, f.err
	}
	return f.result, nil
}

func TestAuthRequestOrchestratorGuardsAndBootstrapSuccess(t *testing.T) {
	t.Run("dependency guards", func(t *testing.T) {
		svc := orchestration.NewAuthRequestOrchestratorService()
		assertOrchestratorError(t, func() error {
			_, err := svc.HandleBootstrapChallenge(context.Background(), nil)
			return err
		}(), modelsystem.ErrChallengeRequestNil.Error())
		assertOrchestratorError(t, func() error {
			_, err := svc.HandleBootstrapAuthenticate(context.Background(), &authmodel.BootstrapAuthRequest{})
			return err
		}(), modelsystem.ErrBootstrapDepsNotReady.Error())
		assertOrchestratorError(t, func() error {
			_, err := svc.HandleUserPasswordAuth(context.Background(), &orchestrationif.UserPasswordAuthRequest{Username: "alice", Password: "secret"})
			return err
		}(), modelsystem.ErrUserCredentialDepsNotReady.Error())
		assertOrchestratorError(t, func() error {
			_, err := svc.HandleTokenVerify(context.Background(), nil)
			return err
		}(), modelsystem.ErrRawTokenRequired.Error())
		assertOrchestratorError(t, func() error {
			_, err := svc.HandleSessionValidate(context.Background(), nil)
			return err
		}(), modelsystem.ErrSessionValidateRequestNil.Error())
		assertOrchestratorError(t, func() error {
			_, err := svc.HandleTokenRefresh(context.Background(), nil)
			return err
		}(), modelsystem.ErrRefreshTokenRequired.Error())
		assertOrchestratorError(t, func() error {
			return svc.HandleTokenRevoke(context.Background(), nil)
		}(), modelsystem.ErrTokenRevokeRequestNil.Error())
	})

	t.Run("bootstrap success", func(t *testing.T) {
		dir := t.TempDir()
		writeOrchestratorEd25519KeyPair(t, dir)

		keySvc, err := commonservice.NewSecretKeyServiceFromStartupParams(modelsystem.SecretKeyStartupParams{
			SecretKeyDir: dir,
			EntityType:   "service",
			EntityID:     "service-1",
			EntityName:   "certification_server",
			InstanceID:   "service-1",
			InstanceName: "certification_server",
		}, nil, nil)
		if err != nil {
			t.Fatalf("unexpected key service error: %v", err)
		}
		sessionSvc := commonservice.NewSessionService(nil)
		tokenSvc := commonservice.NewTokenService(nil, nil)
		orchestrator := orchestration.NewAuthRequestOrchestratorServiceWithDeps(keySvc, sessionSvc, tokenSvc, nil)

		challenge, err := orchestrator.HandleBootstrapChallenge(context.Background(), &authmodel.ChallengeRequest{
			EntityType: commonmodel.EntityService,
			EntityID:   "service-1",
			Audience:   "internal",
			TTLSec:     60,
		})
		if err != nil {
			t.Fatalf("unexpected challenge error: %v", err)
		}
		if challenge == nil || challenge.ChallengeID == uuid.Nil {
			t.Fatalf("expected challenge payload")
		}

		privateRef, err := keySvc.GetPrivateKeyRef(context.Background())
		if err != nil {
			t.Fatalf("unexpected private key ref error: %v", err)
		}
		payload, err := buildBootstrapSignaturePayload(challenge)
		if err != nil {
			t.Fatalf("unexpected signature payload error: %v", err)
		}
		signature, err := (&utils.CryptoUtils{}).SignByAlgorithm(string(commsecmodel.SignatureEd25519), payload, []byte(privateRef.PrivateKeyRef))
		if err != nil {
			t.Fatalf("unexpected signing error: %v", err)
		}

		result, err := orchestrator.HandleBootstrapAuthenticate(context.Background(), &authmodel.BootstrapAuthRequest{
			Challenge: *challenge,
			Signed: authmodel.SignedChallengeResponse{
				ChallengeID:        challenge.ChallengeID,
				KeyID:              challenge.KeyID,
				SignatureAlgorithm: commsecmodel.SignatureEd25519,
				Signature:          signature,
			},
			Scopes: []string{"service:bootstrap"},
			Role:   "service",
		})
		if err != nil {
			t.Fatalf("unexpected bootstrap authenticate error: %v", err)
		}
		if result == nil || result.Session == nil || result.Tokens.AccessToken == nil || result.Tokens.RefreshToken == nil {
			t.Fatalf("expected bootstrap result with session and tokens")
		}
		if result.Stage != authmodel.BootstrapStageReady {
			t.Fatalf("expected ready stage, got %s", result.Stage)
		}
		if result.ActiveCommKeyID != challenge.KeyID {
			t.Fatalf("expected active comm key id %q, got %q", challenge.KeyID, result.ActiveCommKeyID)
		}
		if result.Identity == nil || result.Identity.SessionID != result.Session.ID {
			t.Fatalf("expected identity to reference session")
		}

		validatedSession, err := sessionSvc.ValidateSession(context.Background(), &commonif.SessionValidateRequest{
			SessionID:     result.Session.ID,
			PrincipalID:   result.Session.PrincipalID,
			RequireActive: true,
		})
		if err != nil {
			t.Fatalf("unexpected session validation error: %v", err)
		}
		if validatedSession.ID != result.Session.ID {
			t.Fatalf("expected validated session id %s, got %s", result.Session.ID, validatedSession.ID)
		}

		verification, err := tokenSvc.VerifyToken(context.Background(), &commonif.TokenVerifyRequest{RawToken: result.Tokens.AccessToken.Raw})
		if err != nil {
			t.Fatalf("unexpected token verification error: %v", err)
		}
		if !verification.Valid {
			t.Fatalf("expected verified token, got %+v", verification)
		}
	})
}

func TestAuthRequestOrchestratorSmokePaths(t *testing.T) {
	dir := t.TempDir()
	writeOrchestratorEd25519KeyPair(t, dir)

	keySvc, err := commonservice.NewSecretKeyServiceFromStartupParams(modelsystem.SecretKeyStartupParams{
		SecretKeyDir: dir,
		EntityType:   "service",
		EntityID:     "service-1",
		EntityName:   "certification_server",
		InstanceID:   "service-1",
		InstanceName: "certification_server",
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected key service error: %v", err)
	}
	credentialSvc := &fakeCredentialManager{result: &commonif.UserCredentialValidationResult{
		Principal:     authmodel.Principal{EntityType: commonmodel.EntityUser, EntityID: "alice"},
		Role:          "admin",
		Scopes:        []string{"user:read", "user:write"},
		UserProfileID: uuid.MustParse("11111111-1111-1111-1111-111111111111"),
	}}
	sessionSvc := commonservice.NewSessionService(nil)
	tokenSvc := commonservice.NewTokenService(nil, nil)
	orchestrator := orchestration.NewAuthRequestOrchestratorServiceWithDeps(keySvc, sessionSvc, tokenSvc, credentialSvc)

	challenge, err := orchestrator.HandleBootstrapChallenge(context.Background(), &authmodel.ChallengeRequest{
		EntityType: commonmodel.EntityService,
		EntityID:   "service-1",
		Audience:   "internal",
		TTLSec:     60,
	})
	if err != nil {
		t.Fatalf("unexpected bootstrap challenge error: %v", err)
	}
	privateRef, err := keySvc.GetPrivateKeyRef(context.Background())
	if err != nil {
		t.Fatalf("unexpected private key ref error: %v", err)
	}
	bootstrapPayload, err := buildBootstrapSignaturePayload(challenge)
	if err != nil {
		t.Fatalf("unexpected bootstrap payload error: %v", err)
	}
	bootstrapSignature, err := (&utils.CryptoUtils{}).SignByAlgorithm(string(commsecmodel.SignatureEd25519), bootstrapPayload, []byte(privateRef.PrivateKeyRef))
	if err != nil {
		t.Fatalf("unexpected bootstrap signature error: %v", err)
	}
	bootstrapResult, err := orchestrator.HandleBootstrapAuthenticate(context.Background(), &authmodel.BootstrapAuthRequest{
		Challenge: *challenge,
		Signed: authmodel.SignedChallengeResponse{
			ChallengeID:        challenge.ChallengeID,
			KeyID:              challenge.KeyID,
			SignatureAlgorithm: commsecmodel.SignatureEd25519,
			Signature:          bootstrapSignature,
		},
		Scopes: []string{"service:bootstrap"},
		Role:   "service",
	})
	if err != nil {
		t.Fatalf("unexpected bootstrap authenticate error: %v", err)
	}
	if bootstrapResult.Session == nil || bootstrapResult.Tokens.AccessToken == nil || bootstrapResult.Tokens.RefreshToken == nil {
		t.Fatalf("expected bootstrap session and tokens")
	}

	passwordResult, err := orchestrator.HandleUserPasswordAuth(context.Background(), &orchestrationif.UserPasswordAuthRequest{
		Username:  "alice",
		Password:  "secret-password",
		Audience:  "client",
		Scopes:    []string{"user:read"},
		ClientID:  "client-1",
		GatewayID: "gateway-1",
	})
	if err != nil {
		t.Fatalf("unexpected password auth error: %v", err)
	}
	if passwordResult.Session == nil || passwordResult.Tokens.RefreshToken == nil {
		t.Fatalf("expected password auth to return session and refresh token")
	}

	refreshedTokens, err := orchestrator.HandleTokenRefresh(context.Background(), &commonif.TokenRefreshRequest{RefreshToken: passwordResult.Tokens.RefreshToken.Raw})
	if err != nil {
		t.Fatalf("unexpected token refresh error: %v", err)
	}
	if refreshedTokens == nil || refreshedTokens.AccessToken == nil || refreshedTokens.RefreshToken == nil {
		t.Fatalf("expected refreshed token bundle")
	}

	validatedSession, err := orchestrator.HandleSessionValidate(context.Background(), &commonif.SessionValidateRequest{
		SessionID:     passwordResult.Session.ID,
		PrincipalID:   passwordResult.Session.PrincipalID,
		RequireActive: true,
	})
	if err != nil {
		t.Fatalf("unexpected session validate error: %v", err)
	}
	if validatedSession.ID != passwordResult.Session.ID {
		t.Fatalf("expected session validate to return the same session")
	}
}
