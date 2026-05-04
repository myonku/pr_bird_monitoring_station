package gatewayhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	businessv1 "gateway/src/gen/business/v1"
	authif "gateway/src/iface/auth"
	authcontrolif "gateway/src/iface/authcontrol"
	commonif "gateway/src/iface/common"
	communicationif "gateway/src/iface/communication"
	authmodel "gateway/src/models/auth"
	appclientauthdto "gateway/src/models/auth_dto/app_client"
	modelsystem "gateway/src/models/system"
	http_handler "gateway/src/services/http"

	"github.com/google/uuid"
)

func TestLookupRouteSpecMapsTargets(t *testing.T) {
	tests := []struct {
		name                   string
		method                 string
		path                   string
		expectedKind           http_handler.RouteKind
		expectedTargetService  string
		expectedAuthRoute      http_handler.AuthRouteKind
		expectedRouteKeyPrefix string
	}{
		{
			name:         "health check",
			method:       http.MethodGet,
			path:         "/health",
			expectedKind: http_handler.RouteKindHealth,
		},
		{
			name:                  "client auth sign in",
			method:                http.MethodPost,
			path:                  "/v1/client/auth/sign-in",
			expectedKind:          http_handler.RouteKindAuth,
			expectedTargetService: "certification_server",
			expectedAuthRoute:     http_handler.AuthRouteClientSignIn,
		},
		{
			name:                  "client business profile",
			method:                http.MethodGet,
			path:                  "/v1/client/users/profile",
			expectedKind:          http_handler.RouteKindBusiness,
			expectedTargetService: "data_server",
		},
		{
			name:                  "edge business upload",
			method:                http.MethodPost,
			path:                  "/v1/edge/events",
			expectedKind:          http_handler.RouteKindBusiness,
			expectedTargetService: "data_worker",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec, ok := http_handler.LookupRouteSpec(tc.method, tc.path)
			if !ok {
				t.Fatalf("expected route spec for %s %s", tc.method, tc.path)
			}
			if spec.Kind != tc.expectedKind {
				t.Fatalf("kind = %s, want %s", spec.Kind, tc.expectedKind)
			}
			if spec.ExpectedTargetService != tc.expectedTargetService {
				t.Fatalf("target service = %s, want %s", spec.ExpectedTargetService, tc.expectedTargetService)
			}
			if tc.expectedAuthRoute != "" && spec.AuthRoute != tc.expectedAuthRoute {
				t.Fatalf("auth route = %s, want %s", spec.AuthRoute, tc.expectedAuthRoute)
			}
		})
	}
}

func TestServeHTTP_HealthRouteReturnsOk(t *testing.T) {
	handler := http_handler.NewGatewayHTTPHandler(
		modelsystem.RuntimeConfig{ServiceName: "gateway", InstanceID: "gateway", RunMode: modelsystem.RuntimeRunModeDevelopment},
		nil,
		nil,
		nil,
		nil,
		nil,
	)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != "ok" {
		t.Fatalf("body = %q, want %q", got, "ok")
	}
}

func TestServeHTTP_RoutesAuthRequestToExternalAuthClient(t *testing.T) {
	pipe := &fakeRoutingPipeline{
		profile: &commonif.RouteProfile{
			TargetServiceName: "certification_server",
			TargetEndpoint:    "certification.example:9443",
			FlowCategory:      commonif.FlowCategoryExternalAuthRelay,
		},
	}
	authControl := &fakeAuthControl{}
	externalClient := &fakeExternalAuthClient{
		userPasswordResult: &communicationif.UserPasswordAuthResult{
			Identity: &authmodel.IdentityContext{
				Principal:     authmodel.Principal{EntityType: authmodel.EntityUser, EntityID: "alice"},
				PrincipalID:   "user:alice",
				SessionID:     uuid.MustParse("11111111-1111-1111-1111-111111111111"),
				TokenID:       uuid.MustParse("22222222-2222-2222-2222-222222222222"),
				TokenFamilyID: uuid.MustParse("33333333-3333-3333-3333-333333333333"),
				TokenType:     authmodel.TokenAccess,
			},
			Tokens: authmodel.TokenBundle{
				AccessToken:  &authmodel.IssuedToken{Raw: "access-123", Type: authmodel.TokenAccess, TTLSec: 3600},
				RefreshToken: &authmodel.IssuedToken{Raw: "refresh-456", Type: authmodel.TokenRefresh, TTLSec: 7200},
			},
			IssuedAt:  time.Unix(1700000000, 0).UTC(),
			ExpiresAt: time.Unix(1700003600, 0).UTC(),
		},
	}
	businessClient := &fakeBusinessClient{response: &businessv1.BusinessForwardResponse{Accepted: true}}

	handler := http_handler.NewGatewayHTTPHandler(
		modelsystem.RuntimeConfig{ServiceName: "gateway", InstanceID: "gateway", RunMode: modelsystem.RuntimeRunModeDevelopment},
		pipe,
		authControl,
		func(endpoint string) http_handler.BusinessForwardClient { return businessClient },
		func(endpoint string) http_handler.ExternalAuthClient { return externalClient },
		nil,
	)

	req := httptest.NewRequest(http.MethodPost, "/v1/client/auth/sign-in", strings.NewReader(`{"identifier":"alice","password":"secret"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if externalClient.userPasswordCalls != 1 {
		t.Fatalf("AuthenticateUserPassword calls = %d, want 1", externalClient.userPasswordCalls)
	}
	if authControl.calls != 0 {
		t.Fatalf("authcontrol calls = %d, want 0", authControl.calls)
	}
	if businessClient.calls != 0 {
		t.Fatalf("business forward calls = %d, want 0", businessClient.calls)
	}
	if pipe.lastFlow == nil || pipe.lastFlow.RouteKey != "auth.external.forward.user_password" {
		t.Fatalf("unexpected flow route key: %+v", pipe.lastFlow)
	}

	var response appclientauthdto.ClientAuthCredentialsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.AccessToken != "access-123" {
		t.Fatalf("access token = %q, want %q", response.AccessToken, "access-123")
	}
	if response.PrincipalID != "user:alice" {
		t.Fatalf("principal id = %q, want %q", response.PrincipalID, "user:alice")
	}
}

func TestServeHTTP_RoutesBusinessRequestThroughAuthControlAndBusinessClient(t *testing.T) {
	identity := &authmodel.IdentityContext{
		Principal:     authmodel.Principal{EntityType: authmodel.EntityUser, EntityID: "alice"},
		PrincipalID:   "user:alice",
		SessionID:     uuid.MustParse("44444444-4444-4444-4444-444444444444"),
		TokenID:       uuid.MustParse("55555555-5555-5555-5555-555555555555"),
		TokenFamilyID: uuid.MustParse("66666666-6666-6666-6666-666666666666"),
		TokenType:     authmodel.TokenAccess,
		AuthMethod:    authmodel.AuthMethodPassword,
		ClientID:      "client-1",
		GatewayID:     "gateway-1",
		SourceIP:      "127.0.0.1",
		UserAgent:     "test-agent",
		IssuedAt:      time.Unix(1700000000, 0).UTC(),
		ExpiresAt:     time.Unix(1700003600, 0).UTC(),
	}
	pipe := &fakeRoutingPipeline{
		profile: &commonif.RouteProfile{
			TargetServiceName: "data_server",
			TargetEndpoint:    "data.example:9000",
			TargetServiceType: commonif.TargetServiceTypeInternal,
			FlowCategory:      commonif.FlowCategoryBusinessForward,
		},
	}
	authControl := &fakeAuthControl{
		result: &authcontrolif.AuthControlResult{
			Identity:          identity,
			RateLimitDecision: &authmodel.RateLimitDecision{Allowed: true},
		},
	}
	businessClient := &fakeBusinessClient{response: &businessv1.BusinessForwardResponse{Accepted: true, Payload: `{"ok":true}`}}

	handler := http_handler.NewGatewayHTTPHandler(
		modelsystem.RuntimeConfig{ServiceName: "gateway", InstanceID: "gateway", RunMode: modelsystem.RuntimeRunModeDevelopment},
		pipe,
		authControl,
		func(endpoint string) http_handler.BusinessForwardClient { return businessClient },
		func(endpoint string) http_handler.ExternalAuthClient { return &fakeExternalAuthClient{} },
		nil,
	)

	req := httptest.NewRequest(http.MethodGet, "/v1/client/users/profile?identifier=alice", nil)
	req.Header.Set("Authorization", "Bearer raw-token")
	req.Header.Set("X-Client-Id", "client-1")
	req.Header.Set("X-Audience", "client-app")
	req.Header.Set("X-Scopes", "read,write")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if authControl.calls != 1 {
		t.Fatalf("authcontrol calls = %d, want 1", authControl.calls)
	}
	if authControl.lastReq == nil || authControl.lastReq.Authorization == nil || authControl.lastReq.Authorization.RawToken != "raw-token" {
		t.Fatalf("unexpected auth control request: %+v", authControl.lastReq)
	}
	if authControl.lastReq.RateLimit == nil || authControl.lastReq.RateLimit.TargetService != "data_server" {
		t.Fatalf("unexpected rate limit request: %+v", authControl.lastReq.RateLimit)
	}
	if businessClient.calls != 1 {
		t.Fatalf("business forward calls = %d, want 1", businessClient.calls)
	}
	if businessClient.lastReq == nil {
		t.Fatal("business request was not captured")
	}
	if businessClient.lastReq.TargetServiceName != "data_server" {
		t.Fatalf("target service = %q, want %q", businessClient.lastReq.TargetServiceName, "data_server")
	}
	if businessClient.lastReq.Operation != "client.users.profile" {
		t.Fatalf("operation = %q, want %q", businessClient.lastReq.Operation, "client.users.profile")
	}
	if businessClient.lastReq.AuthContext == nil || businessClient.lastReq.AuthContext.PrincipalId != "user:alice" {
		t.Fatalf("unexpected auth context: %+v", businessClient.lastReq.AuthContext)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != `{"ok":true}` {
		t.Fatalf("body = %s, want %s", got, `{"ok":true}`)
	}
}

func TestServeHTTP_RecordsCursorQueryKeepsCursorAsString(t *testing.T) {
	pipe := &fakeRoutingPipeline{
		profile: &commonif.RouteProfile{
			TargetServiceName: "data_server",
			TargetEndpoint:    "data.example:9000",
			TargetServiceType: commonif.TargetServiceTypeInternal,
			FlowCategory:      commonif.FlowCategoryBusinessForward,
		},
	}
	authControl := &fakeAuthControl{
		result: &authcontrolif.AuthControlResult{
			RateLimitDecision: &authmodel.RateLimitDecision{Allowed: true},
		},
	}
	businessClient := &fakeBusinessClient{response: &businessv1.BusinessForwardResponse{Accepted: true, Payload: `{"items":[],"has_more":false}`}}

	handler := http_handler.NewGatewayHTTPHandler(
		modelsystem.RuntimeConfig{ServiceName: "gateway", InstanceID: "gateway", RunMode: modelsystem.RuntimeRunModeDevelopment},
		pipe,
		authControl,
		func(endpoint string) http_handler.BusinessForwardClient { return businessClient },
		func(endpoint string) http_handler.ExternalAuthClient { return &fakeExternalAuthClient{} },
		nil,
	)

	req := httptest.NewRequest(http.MethodGet, "/v1/client/records?cursor=0&limit=20", nil)
	req.Header.Set("Authorization", "Bearer raw-token")
	req.Header.Set("X-Client-Id", "client-1")
	req.Header.Set("X-Audience", "client-app")
	req.Header.Set("X-Scopes", "read,write")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if businessClient.calls != 1 {
		t.Fatalf("business forward calls = %d, want 1", businessClient.calls)
	}
	if businessClient.lastReq == nil {
		t.Fatal("business request was not captured")
	}
	if !strings.Contains(businessClient.lastReq.Payload, `"cursor":"0"`) {
		t.Fatalf("payload = %s, want cursor to remain a string", businessClient.lastReq.Payload)
	}
	if strings.Contains(businessClient.lastReq.Payload, `"cursor":0`) {
		t.Fatalf("payload unexpectedly coerced cursor to number: %s", businessClient.lastReq.Payload)
	}
}

func TestServeHTTP_NoAuthModeSkipsAuthControlForBusinessRoute(t *testing.T) {
	pipe := &fakeRoutingPipeline{
		profile: &commonif.RouteProfile{
			TargetServiceName: "data_server",
			TargetEndpoint:    "data.example:9000",
			TargetServiceType: commonif.TargetServiceTypeInternal,
			FlowCategory:      commonif.FlowCategoryBusinessForward,
		},
	}
	authControl := &fakeAuthControl{result: &authcontrolif.AuthControlResult{RateLimitDecision: &authmodel.RateLimitDecision{Allowed: true}}}
	businessClient := &fakeBusinessClient{response: &businessv1.BusinessForwardResponse{Accepted: true, Payload: `{"ok":true}`}}

	handler := http_handler.NewGatewayHTTPHandler(
		modelsystem.RuntimeConfig{ServiceName: "gateway", InstanceID: "gateway", RunMode: modelsystem.RuntimeRunModeNoAuth},
		pipe,
		authControl,
		func(endpoint string) http_handler.BusinessForwardClient { return businessClient },
		func(endpoint string) http_handler.ExternalAuthClient { return &fakeExternalAuthClient{} },
		nil,
	)

	req := httptest.NewRequest(http.MethodGet, "/v1/client/users/profile?identifier=alice", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if authControl.calls != 0 {
		t.Fatalf("authcontrol calls = %d, want 0 in no-auth mode", authControl.calls)
	}
	if businessClient.calls != 1 {
		t.Fatalf("business forward calls = %d, want 1", businessClient.calls)
	}
	if businessClient.lastReq == nil || businessClient.lastReq.AuthContext != nil {
		t.Fatalf("expected no auth context in no-auth mode, got %+v", businessClient.lastReq)
	}
}

func TestServeHTTP_NoAuthModeDisablesAuthRoutes(t *testing.T) {
	pipe := &fakeRoutingPipeline{
		profile: &commonif.RouteProfile{
			TargetServiceName: "certification_server",
			TargetEndpoint:    "certification.example:9443",
			FlowCategory:      commonif.FlowCategoryExternalAuthRelay,
		},
	}
	externalClient := &fakeExternalAuthClient{
		userPasswordResult: &communicationif.UserPasswordAuthResult{
			Identity: &authmodel.IdentityContext{
				Principal:   authmodel.Principal{EntityType: authmodel.EntityUser, EntityID: "alice"},
				PrincipalID: "user:alice",
			},
		},
	}

	handler := http_handler.NewGatewayHTTPHandler(
		modelsystem.RuntimeConfig{ServiceName: "gateway", InstanceID: "gateway", RunMode: modelsystem.RuntimeRunModeNoAuth},
		pipe,
		nil,
		func(endpoint string) http_handler.BusinessForwardClient { return &fakeBusinessClient{} },
		func(endpoint string) http_handler.ExternalAuthClient { return externalClient },
		nil,
	)

	req := httptest.NewRequest(http.MethodPost, "/v1/client/auth/sign-in", strings.NewReader(`{"identifier":"alice","password":"secret"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	if externalClient.userPasswordCalls != 0 {
		t.Fatalf("AuthenticateUserPassword calls = %d, want 0 in no-auth mode", externalClient.userPasswordCalls)
	}
	if pipe.lastFlow != nil {
		t.Fatalf("expected no route resolution in no-auth mode, got %+v", pipe.lastFlow)
	}
}

type fakeRoutingPipeline struct {
	profile  *commonif.RouteProfile
	lastFlow *commonif.FlowRouteInput
}

func (f *fakeRoutingPipeline) ResolveRouteProfile(ctx context.Context, flow *commonif.FlowRouteInput) (*commonif.RouteProfile, error) {
	f.lastFlow = flow
	if f.profile == nil {
		return nil, errors.New("route profile not configured")
	}
	return f.profile, nil
}

func (f *fakeRoutingPipeline) ClassifyFlow(ctx context.Context, flow *commonif.FlowRouteInput) (commonif.FlowCategory, error) {
	return commonif.FlowCategoryBusinessForward, nil
}

func (f *fakeRoutingPipeline) BuildOutboundPayload(ctx context.Context, req *communicationif.BuildOutboundPayloadRequest) (*communicationif.OutboundPayloadPlan, error) {
	return &communicationif.OutboundPayloadPlan{}, nil
}

type fakeAuthControl struct {
	calls   int
	lastReq *authcontrolif.AuthControlRequest
	result  *authcontrolif.AuthControlResult
}

func (f *fakeAuthControl) Enforce(ctx context.Context, req *authcontrolif.AuthControlRequest) (*authcontrolif.AuthControlResult, error) {
	f.calls++
	f.lastReq = req
	if f.result != nil {
		return f.result, nil
	}
	return &authcontrolif.AuthControlResult{RateLimitDecision: &authmodel.RateLimitDecision{Allowed: true}}, nil
}

type fakeExternalAuthClient struct {
	userPasswordCalls  int
	lastUserPassword   *communicationif.UserPasswordAuthRequest
	userPasswordResult *communicationif.UserPasswordAuthResult
}

func (f *fakeExternalAuthClient) AuthenticateUserPassword(ctx context.Context, req *communicationif.UserPasswordAuthRequest) (*communicationif.UserPasswordAuthResult, error) {
	f.userPasswordCalls++
	f.lastUserPassword = req
	if f.userPasswordResult != nil {
		return f.userPasswordResult, nil
	}
	return nil, errors.New("unexpected AuthenticateUserPassword call")
}

func (f *fakeExternalAuthClient) ForwardRefreshTokenBundle(ctx context.Context, req *authif.TokenRefreshRequest) (*authmodel.TokenBundle, error) {
	return nil, errors.New("unexpected ForwardRefreshTokenBundle call")
}

func (f *fakeExternalAuthClient) ForwardBootstrapChallenge(ctx context.Context, req *authmodel.ChallengeRequest) (*authmodel.ChallengePayload, error) {
	return nil, errors.New("unexpected ForwardBootstrapChallenge call")
}

func (f *fakeExternalAuthClient) ForwardBootstrapAuthenticate(ctx context.Context, req *authmodel.BootstrapAuthRequest) (*authmodel.BootstrapAuthResult, error) {
	return nil, errors.New("unexpected ForwardBootstrapAuthenticate call")
}

type fakeBusinessClient struct {
	calls    int
	lastReq  *businessv1.BusinessForwardRequest
	response *businessv1.BusinessForwardResponse
	callErr  error
}

func (f *fakeBusinessClient) ForwardBusiness(ctx context.Context, req *businessv1.BusinessForwardRequest) (*businessv1.BusinessForwardResponse, error) {
	f.calls++
	f.lastReq = req
	if f.callErr != nil {
		return nil, f.callErr
	}
	if f.response != nil {
		return f.response, nil
	}
	return &businessv1.BusinessForwardResponse{Accepted: true}, nil
}
