package authcontrolsvc_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	authif "gateway/src/iface/auth"
	authcontrolif "gateway/src/iface/authcontrol"
	commonif "gateway/src/iface/common"
	authmodel "gateway/src/models/auth"
	commonmodel "gateway/src/models/common"
	modelsystem "gateway/src/models/system"
	authcontrolsvc "gateway/src/services/authcontrol"
)

type recordingRateLimiter struct {
	calls          int
	lastDescriptor *authmodel.RateLimitDescriptor
	decision       *authmodel.RateLimitDecision
}

func (r *recordingRateLimiter) Decide(ctx context.Context, descriptor *authmodel.RateLimitDescriptor) (*authmodel.RateLimitDecision, error) {
	_ = ctx
	r.calls++
	r.lastDescriptor = descriptor
	if r.decision != nil {
		return r.decision, nil
	}
	return &authmodel.RateLimitDecision{Allowed: true, Remaining: 1, SubjectKey: "ok", Reason: "allowed"}, nil
}

type recordingRemoteAuthClient struct {
	verifyCalls   int
	sessionCalls  int
	verifyReq     *authif.TokenVerifyRequest
	sessionReq    *authif.SessionValidateRequest
	verifyResult  *authmodel.TokenVerificationResult
	sessionResult *authmodel.Session
}

func (r *recordingRemoteAuthClient) VerifyToken(ctx context.Context, req *authif.TokenVerifyRequest) (*authmodel.TokenVerificationResult, error) {
	_ = ctx
	r.verifyCalls++
	r.verifyReq = req
	if r.verifyResult != nil {
		return r.verifyResult, nil
	}
	return &authmodel.TokenVerificationResult{Valid: true}, nil
}

func (r *recordingRemoteAuthClient) ValidateSession(ctx context.Context, req *authif.SessionValidateRequest) (*authmodel.Session, error) {
	_ = ctx
	r.sessionCalls++
	r.sessionReq = req
	if r.sessionResult != nil {
		return r.sessionResult, nil
	}
	return &authmodel.Session{Status: authmodel.SessionActive}, nil
}

type stubServiceResolver struct {
	targetEndpoint string
	lastFlow       *commonif.FlowRouteInput
}

func (s *stubServiceResolver) ResolveServiceType(ctx context.Context, flow *commonif.FlowRouteInput) (commonif.TargetServiceType, error) {
	_ = ctx
	_ = flow
	return commonif.TargetServiceTypeAuthAuthority, nil
}

func (s *stubServiceResolver) ResolveTargetInstance(ctx context.Context, flow *commonif.FlowRouteInput) (*commonmodel.ServiceInstance, error) {
	_ = ctx
	s.lastFlow = flow
	return &commonmodel.ServiceInstance{Endpoint: s.targetEndpoint}, nil
}

func (s *stubServiceResolver) ResolveRouteProfile(ctx context.Context, flow *commonif.FlowRouteInput) (*commonif.RouteProfile, error) {
	_ = ctx
	_ = flow
	return &commonif.RouteProfile{
		TargetServiceType: commonif.TargetServiceTypeAuthAuthority,
		TargetServiceName: "certification_server",
		TargetEndpoint:    s.targetEndpoint,
	}, nil
}

func TestGatewayAuthControlServiceNoAuthBypassesRateLimiter(t *testing.T) {
	limiter := &recordingRateLimiter{
		decision: &authmodel.RateLimitDecision{Allowed: false, Reason: "should not be used"},
	}

	svc := authcontrolsvc.NewGatewayAuthControlService(
		modelsystem.RuntimeRunModeNoAuth,
		nil,
		limiter,
		nil,
	)

	result, err := svc.Enforce(context.Background(), &authcontrolif.AuthControlRequest{
		Purpose: authcontrolif.AuthControlPurposeInbound,
		RateLimit: &authcontrolif.RateLimitInput{
			Scope:  authmodel.RateLimitScopeAuth,
			Route:  "business.forward.generic",
			Method: "POST",
		},
	})
	if err != nil {
		t.Fatalf("Enforce returned error: %v", err)
	}
	if limiter.calls != 0 {
		t.Fatalf("expected limiter to be bypassed, got %d calls", limiter.calls)
	}
	if result == nil || result.RateLimitDecision == nil || !result.RateLimitDecision.Allowed {
		t.Fatalf("expected allowed decision in no_auth mode, got %#v", result)
	}
}

func TestGatewayAuthControlServiceUsesRemoteAuthAndRateLimiter(t *testing.T) {
	limiter := &recordingRateLimiter{}
	remoteClient := &recordingRemoteAuthClient{
		verifyResult: &authmodel.TokenVerificationResult{
			Valid:  true,
			Status: authmodel.TokenStatusActive,
			Token: &authmodel.TokenRecord{
				ID:          mustUUID("11111111-1111-1111-1111-111111111111"),
				FamilyID:    mustUUID("22222222-2222-2222-2222-222222222222"),
				SessionID:   mustUUID("33333333-3333-3333-3333-333333333333"),
				Type:        authmodel.TokenAccess,
				PrincipalID: "user:u-1",
				Principal: authmodel.Principal{
					EntityType: authmodel.EntityUser,
					EntityID:   "u-1",
				},
			},
		},
		sessionResult: &authmodel.Session{
			ID:          mustUUID("33333333-3333-3333-3333-333333333333"),
			PrincipalID: "user:u-1",
			Principal: authmodel.Principal{
				EntityType: authmodel.EntityUser,
				EntityID:   "u-1",
			},
			EntityType: authmodel.EntityUser,
			EntityID:   "u-1",
			Status:     authmodel.SessionActive,
		},
	}
	resolver := &stubServiceResolver{targetEndpoint: "127.0.0.1:9001"}

	svc := authcontrolsvc.NewGatewayAuthControlService(
		modelsystem.RuntimeRunModeDevelopment,
		resolver,
		limiter,
		func(endpoint string) authcontrolsvc.IRemoteAuthClient {
			if endpoint != "127.0.0.1:9001" {
				t.Fatalf("unexpected endpoint passed to factory: %s", endpoint)
			}
			return remoteClient
		},
	)

	result, err := svc.Enforce(context.Background(), &authcontrolif.AuthControlRequest{
		Purpose: authcontrolif.AuthControlPurposeInbound,
		Authorization: &authcontrolif.AuthorizationInput{
			RawToken:            "  bearer-token  ",
			SessionID:           mustUUID("33333333-3333-3333-3333-333333333333"),
			PrincipalID:         "user:u-1",
			RequireActive:       true,
			MinVersion:          7,
			ExpectedAudience:    "gateway",
			RequireScopes:       []string{"read:birds"},
			AllowExpiredSkewSec: 15,
		},
		RateLimit: &authcontrolif.RateLimitInput{
			Route:         "business.forward.generic",
			Method:        "POST",
			Transport:     "grpc",
			SourceService: "gateway",
			TargetService: "certification_server",
		},
	})
	if err != nil {
		t.Fatalf("Enforce returned error: %v", err)
	}
	if resolver.lastFlow == nil || resolver.lastFlow.RouteKey != "auth.remote.verify.token" {
		t.Fatalf("expected remote auth route lookup, got %#v", resolver.lastFlow)
	}
	if remoteClient.verifyCalls != 1 {
		t.Fatalf("expected one token verification call, got %d", remoteClient.verifyCalls)
	}
	if remoteClient.sessionCalls != 1 {
		t.Fatalf("expected one session validation call, got %d", remoteClient.sessionCalls)
	}
	if remoteClient.verifyReq == nil || remoteClient.verifyReq.RawToken != "bearer-token" {
		t.Fatalf("unexpected verify request: %#v", remoteClient.verifyReq)
	}
	if remoteClient.sessionReq == nil || !remoteClient.sessionReq.RequireActive || remoteClient.sessionReq.MinVersion != 7 {
		t.Fatalf("unexpected session request: %#v", remoteClient.sessionReq)
	}
	if limiter.calls != 1 {
		t.Fatalf("expected one limiter decision, got %d", limiter.calls)
	}
	if limiter.lastDescriptor == nil || !limiter.lastDescriptor.Authenticated {
		t.Fatalf("expected authenticated descriptor, got %#v", limiter.lastDescriptor)
	}
	if result == nil || result.Identity == nil || result.Identity.PrincipalID != "user:u-1" {
		t.Fatalf("expected identity to be merged from remote auth, got %#v", result)
	}
	if result.TokenVerification == nil || result.TokenVerification.Token == nil {
		t.Fatalf("expected token verification context, got %#v", result)
	}
}

func TestLocalRateLimiterServiceTracksRemaining(t *testing.T) {
	svc := authcontrolsvc.NewLocalRateLimiterService()

	descriptor := &authmodel.RateLimitDescriptor{
		Scope:  authmodel.RateLimitScopeAuth,
		Route:  "business.forward.generic",
		Method: "POST",
		Tags:   map[string]string{"source": "test"},
	}

	firstDecision, err := svc.Decide(context.Background(), descriptor)
	if err != nil {
		t.Fatalf("first Decide returned error: %v", err)
	}
	if !firstDecision.Allowed {
		t.Fatalf("expected first request to be allowed, got %#v", firstDecision)
	}

	secondDecision, err := svc.Decide(context.Background(), descriptor)
	if err != nil {
		t.Fatalf("second Decide returned error: %v", err)
	}
	if !secondDecision.Allowed {
		t.Fatalf("expected second request to still be allowed, got %#v", secondDecision)
	}
	if secondDecision.Remaining >= firstDecision.Remaining {
		t.Fatalf("expected remaining quota to decrease, first=%d second=%d", firstDecision.Remaining, secondDecision.Remaining)
	}
}

func mustUUID(raw string) uuid.UUID {
	parsed, err := uuid.Parse(raw)
	if err != nil {
		panic(err)
	}
	return parsed
}
