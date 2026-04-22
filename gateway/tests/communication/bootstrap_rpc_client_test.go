package communication

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	authv1 "gateway/src/gen/auth/v1"
	authmodel "gateway/src/models/auth"
	commsecmodel "gateway/src/models/commsec"
	rpcclient "gateway/src/services/communication/rpc_client"

	"github.com/google/uuid"
	"google.golang.org/grpc"
)

type bootstrapServiceStub struct {
	authv1.UnimplementedAuthAuthorityBootstrapServiceServer

	mu            sync.Mutex
	challengeReq  *authv1.BootstrapChallengeRequest
	authReq       *authv1.BootstrapAuthenticateRequest
	challengeID   string
	challengeTime time.Time
	authTime      time.Time
}

func (s *bootstrapServiceStub) InitBootstrapChallenge(ctx context.Context, req *authv1.BootstrapChallengeRequest) (*authv1.BootstrapChallengeResponse, error) {
	_ = ctx
	issuedAt := time.Date(2026, 4, 22, 10, 0, 0, 0, time.UTC)
	s.mu.Lock()
	s.challengeReq = req
	s.challengeID = uuid.MustParse("11111111-1111-1111-1111-111111111111").String()
	s.challengeTime = issuedAt
	s.mu.Unlock()

	return &authv1.BootstrapChallengeResponse{
		Challenge: &authv1.ChallengePayload{
			ChallengeId: s.challengeID,
			Issuer:      "certification_server",
			Audience:    req.GetAudience(),
			EntityType:  req.GetEntityType(),
			EntityId:    req.GetEntityId(),
			KeyId:       req.GetKeyId(),
			Nonce:       "nonce-123",
			IssuedAtMs:  issuedAt.UnixMilli(),
			ExpiresAtMs: issuedAt.Add(2 * time.Minute).UnixMilli(),
		},
	}, nil
}

func (s *bootstrapServiceStub) AuthenticateBootstrap(ctx context.Context, req *authv1.BootstrapAuthenticateRequest) (*authv1.BootstrapAuthenticateResponse, error) {
	_ = ctx
	issuedAt := time.Date(2026, 4, 22, 10, 0, 0, 0, time.UTC)
	expiresAt := issuedAt.Add(24 * time.Hour)
	familyID := uuid.MustParse("22222222-2222-2222-2222-222222222222").String()
	sessionID := uuid.MustParse("33333333-3333-3333-3333-333333333333").String()
	s.mu.Lock()
	s.authReq = req
	s.authTime = issuedAt.Add(30 * time.Second)
	s.mu.Unlock()

	return &authv1.BootstrapAuthenticateResponse{
		Stage: authv1.BootstrapStage_BOOTSTRAP_STAGE_READY,
		Identity: &authv1.IdentityContext{
			Principal: &authv1.Principal{
				EntityType:  authv1.EntityType_ENTITY_TYPE_SERVICE,
				EntityId:    req.GetChallenge().GetEntityId(),
				PrincipalId: "service:gateway-instance",
			},
			SessionId:     sessionID,
			TokenId:       uuid.MustParse("44444444-4444-4444-4444-444444444444").String(),
			TokenFamilyId: familyID,
			Role:          "service",
			Scopes:        []string{"gateway:bootstrap"},
			AuthMethod:    "service_secret",
			GatewayId:     req.GetSigned().GetKeyId(),
			SourceService: "gateway",
			TargetService: "certification_server",
			RequestId:     "request-123",
			TraceId:       "trace-123",
			IssuedAtMs:    issuedAt.UnixMilli(),
			ExpiresAtMs:   expiresAt.UnixMilli(),
		},
		Session: &authv1.Session{
			SessionId:        sessionID,
			Principal:        &authv1.Principal{EntityType: authv1.EntityType_ENTITY_TYPE_SERVICE, EntityId: req.GetChallenge().GetEntityId()},
			EntityType:       authv1.EntityType_ENTITY_TYPE_SERVICE,
			EntityId:         req.GetChallenge().GetEntityId(),
			PrincipalId:      "service:gateway-instance",
			Status:           authv1.SessionStatus_SESSION_STATUS_ACTIVE,
			AuthMethod:       authv1.AuthMethod_AUTH_METHOD_SERVICE_SECRET,
			ClientId:         "gateway-client",
			GatewayId:        req.GetSigned().GetKeyId(),
			ScopeSnapshot:    []string{"gateway:bootstrap"},
			RoleSnapshot:     "service",
			TokenFamilyId:    familyID,
			CreatedAtMs:      issuedAt.UnixMilli(),
			UpdatedAtMs:      issuedAt.UnixMilli(),
			LastSeenAtMs:     issuedAt.UnixMilli(),
			LastVerifiedAtMs: issuedAt.Add(1 * time.Minute).UnixMilli(),
			NextRefreshAtMs:  issuedAt.Add(30 * time.Minute).UnixMilli(),
			ExpiresAtMs:      expiresAt.UnixMilli(),
			Version:          7,
		},
		Tokens: &authv1.TokenBundle{
			AccessToken: &authv1.IssuedToken{
				Raw:       "access-token-raw",
				TokenType: authv1.TokenType_TOKEN_TYPE_ACCESS,
				TtlSec:    300,
			},
			RefreshToken: &authv1.IssuedToken{
				Raw:       "refresh-token-raw",
				TokenType: authv1.TokenType_TOKEN_TYPE_REFRESH,
				TtlSec:    86400,
			},
		},
		ActiveCommKeyId: req.GetSigned().GetKeyId(),
		IssuedAtMs:      issuedAt.UnixMilli(),
		ExpiresAtMs:     expiresAt.UnixMilli(),
	}, nil
}

func TestBootstrapRPCClientMapsChallengeAndAuthenticateResponses(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	grpcServer := grpc.NewServer()
	stub := &bootstrapServiceStub{}
	authv1.RegisterAuthAuthorityBootstrapServiceServer(grpcServer, stub)
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- grpcServer.Serve(lis)
	}()
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = lis.Close()
		<-serverDone
	})

	client := rpcclient.NewBootstrapRPCClient(lis.Addr().String())
	challengeSignedAt := time.Date(2026, 4, 22, 10, 0, 30, 0, time.UTC)
	result, err := client.ExecuteBootstrapHandshake(context.Background(), &rpcclient.BootstrapHandshakeRequest{
		EntityType: "service",
		EntityID:   "gateway-instance",
		Audience:   "gateway",
		KeyID:      "gateway-local-key",
		Signer: func(ctx context.Context, payload *authmodel.ChallengePayload) (*authmodel.SignedChallengeResponse, error) {
			_ = ctx
			return &authmodel.SignedChallengeResponse{
				ChallengeID:        payload.ChallengeID,
				KeyID:              "gateway-local-key",
				SignatureAlgorithm: commsecmodel.SignatureEd25519,
				Signature:          "signed-payload",
				SignedAt:           challengeSignedAt,
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("ExecuteBootstrapHandshake returned error: %v", err)
	}

	if result.Stage != "ready" {
		t.Fatalf("stage = %q, want %q", result.Stage, "ready")
	}
	if result.ActiveCommKeyID != "gateway-local-key" {
		t.Fatalf("active comm key id = %q, want %q", result.ActiveCommKeyID, "gateway-local-key")
	}
	if result.IssuedAt.IsZero() || !result.IssuedAt.Equal(time.Date(2026, 4, 22, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("issued at = %v, want fixed bootstrap time", result.IssuedAt)
	}
	if result.ExpiresAt.IsZero() || !result.ExpiresAt.Equal(time.Date(2026, 4, 23, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("expires at = %v, want fixed bootstrap expiry", result.ExpiresAt)
	}

	if result.Identity == nil {
		t.Fatal("expected identity in bootstrap result")
	}
	if result.Identity.EntityType != authmodel.EntityService {
		t.Fatalf("identity entity type = %q, want %q", result.Identity.EntityType, authmodel.EntityService)
	}
	if result.Identity.EntityID != "gateway-instance" {
		t.Fatalf("identity entity id = %q, want %q", result.Identity.EntityID, "gateway-instance")
	}
	if result.Identity.PrincipalID != "service:gateway-instance" {
		t.Fatalf("identity principal id = %q, want %q", result.Identity.PrincipalID, "service:gateway-instance")
	}
	if result.Identity.TokenFamilyID != uuid.MustParse("22222222-2222-2222-2222-222222222222") {
		t.Fatalf("identity token family id = %v, want fixed family id", result.Identity.TokenFamilyID)
	}

	if result.Session == nil {
		t.Fatal("expected session in bootstrap result")
	}
	if result.Session.TokenFamilyID != uuid.MustParse("22222222-2222-2222-2222-222222222222") {
		t.Fatalf("session token family id = %v, want fixed family id", result.Session.TokenFamilyID)
	}
	if result.Session.NextRefreshAt.IsZero() || !result.Session.NextRefreshAt.Equal(time.Date(2026, 4, 22, 10, 30, 0, 0, time.UTC)) {
		t.Fatalf("session next refresh at = %v, want fixed next refresh time", result.Session.NextRefreshAt)
	}

	if result.Tokens.AccessToken == nil || result.Tokens.AccessToken.Raw != "access-token-raw" {
		t.Fatalf("access token = %#v, want raw access-token-raw", result.Tokens.AccessToken)
	}
	if result.Tokens.AccessToken.Type != authmodel.TokenAccess {
		t.Fatalf("access token type = %q, want %q", result.Tokens.AccessToken.Type, authmodel.TokenAccess)
	}
	if result.Tokens.AccessToken.TTLSec != 300 {
		t.Fatalf("access token ttl = %d, want %d", result.Tokens.AccessToken.TTLSec, 300)
	}
	if result.Tokens.RefreshToken == nil || result.Tokens.RefreshToken.Raw != "refresh-token-raw" {
		t.Fatalf("refresh token = %#v, want raw refresh-token-raw", result.Tokens.RefreshToken)
	}
	if result.Tokens.RefreshToken.Type != authmodel.TokenRefresh {
		t.Fatalf("refresh token type = %q, want %q", result.Tokens.RefreshToken.Type, authmodel.TokenRefresh)
	}
	if result.Tokens.RefreshToken.TTLSec != 86400 {
		t.Fatalf("refresh token ttl = %d, want %d", result.Tokens.RefreshToken.TTLSec, 86400)
	}

	stub.mu.Lock()
	challengeReq := stub.challengeReq
	authReq := stub.authReq
	stub.mu.Unlock()
	if challengeReq == nil {
		t.Fatal("expected challenge request to be captured")
	}
	if challengeReq.GetEntityType() != authv1.EntityType_ENTITY_TYPE_SERVICE {
		t.Fatalf("challenge entity type = %v, want %v", challengeReq.GetEntityType(), authv1.EntityType_ENTITY_TYPE_SERVICE)
	}
	if challengeReq.GetEntityId() != "gateway-instance" {
		t.Fatalf("challenge entity id = %q, want %q", challengeReq.GetEntityId(), "gateway-instance")
	}
	if challengeReq.GetKeyId() != "gateway-local-key" {
		t.Fatalf("challenge key id = %q, want %q", challengeReq.GetKeyId(), "gateway-local-key")
	}
	if challengeReq.GetAudience() != "gateway" {
		t.Fatalf("challenge audience = %q, want %q", challengeReq.GetAudience(), "gateway")
	}
	if challengeReq.GetTtlSec() != 60 {
		t.Fatalf("challenge ttl = %d, want %d", challengeReq.GetTtlSec(), 60)
	}
	if authReq == nil {
		t.Fatal("expected authenticate request to be captured")
	}
	if authReq.GetSigned() == nil {
		t.Fatal("expected signed challenge in authenticate request")
	}
	if authReq.GetSigned().GetChallengeId() != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("signed challenge id = %q, want fixed challenge id", authReq.GetSigned().GetChallengeId())
	}
	if authReq.GetSigned().GetKeyId() != "gateway-local-key" {
		t.Fatalf("signed key id = %q, want %q", authReq.GetSigned().GetKeyId(), "gateway-local-key")
	}
	if authReq.GetSigned().GetSignatureAlgorithm() != authv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519 {
		t.Fatalf("signed signature algorithm = %v, want %v", authReq.GetSigned().GetSignatureAlgorithm(), authv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519)
	}
	if authReq.GetSigned().GetSignature() != "signed-payload" {
		t.Fatalf("signed signature = %q, want %q", authReq.GetSigned().GetSignature(), "signed-payload")
	}
	if authReq.GetRole() != "service" {
		t.Fatalf("authenticate role = %q, want %q", authReq.GetRole(), "service")
	}
	if authReq.GetRequireDownstreamToken() {
		t.Fatal("expected downstream token to be disabled in bootstrap request")
	}
}
