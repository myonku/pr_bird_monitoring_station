package gatewayhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	businessv1 "gateway/src/gen/business/v1"
	authif "gateway/src/iface/auth"
	authcontrolif "gateway/src/iface/authcontrol"
	commonif "gateway/src/iface/common"
	communicationif "gateway/src/iface/communication"
	authmodel "gateway/src/models/auth"
	appclientauthdto "gateway/src/models/auth_dto/app_client"
	edgeserverauthdto "gateway/src/models/auth_dto/edge_server"
	commsecmodel "gateway/src/models/commsec"
	modelsystem "gateway/src/models/system"
	rpcclient "gateway/src/services/communication/rpc_client"

	"github.com/google/uuid"
)

type ExternalAuthClient interface {
	AuthenticateUserPassword(ctx context.Context, req *communicationif.UserPasswordAuthRequest) (*communicationif.UserPasswordAuthResult, error)
	ForwardRefreshTokenBundle(ctx context.Context, req *authif.TokenRefreshRequest) (*authmodel.TokenBundle, error)
	ForwardBootstrapChallenge(ctx context.Context, req *authmodel.ChallengeRequest) (*authmodel.ChallengePayload, error)
	ForwardBootstrapAuthenticate(ctx context.Context, req *authmodel.BootstrapAuthRequest) (*authmodel.BootstrapAuthResult, error)
}

type RemoteAuthClient interface {
	ValidateSession(ctx context.Context, req *authif.SessionValidateRequest) (*authmodel.Session, error)
}

type BusinessForwardClient interface {
	ForwardBusiness(ctx context.Context, req *businessv1.BusinessForwardRequest) (*businessv1.BusinessForwardResponse, error)
}

type ExternalAuthClientFactory func(endpoint string) ExternalAuthClient
type RemoteAuthClientFactory func(endpoint string) RemoteAuthClient
type BusinessForwardClientFactory func(endpoint string) BusinessForwardClient

// GatewayHTTPHandler 将外部 HTTP 请求分流到认证 RPC 或统一业务 RPC。
type GatewayHTTPHandler struct {
	runtime modelsystem.RuntimeConfig

	routingPipeline communicationif.IRoutingPayloadPipeline
	authControl     authcontrolif.IGatewayAuthControl

	externalAuthClientFactory ExternalAuthClientFactory
	remoteAuthClientFactory   RemoteAuthClientFactory
	businessClientFactory     BusinessForwardClientFactory
}

// NewGatewayHTTPHandler 构造网关 HTTP 入口。
func NewGatewayHTTPHandler(
	runtime modelsystem.RuntimeConfig,
	routingPipeline communicationif.IRoutingPayloadPipeline,
	authControl authcontrolif.IGatewayAuthControl,
	businessClientFactory BusinessForwardClientFactory,
	externalAuthClientFactory ExternalAuthClientFactory,
	remoteAuthClientFactory RemoteAuthClientFactory,
) http.Handler {
	if businessClientFactory == nil {
		businessClientFactory = func(endpoint string) BusinessForwardClient {
			return rpcclient.NewBusinessForwardRPCClient(endpoint)
		}
	}
	if externalAuthClientFactory == nil {
		externalAuthClientFactory = func(endpoint string) ExternalAuthClient {
			return rpcclient.NewExternalAuthRPCClient(endpoint)
		}
	}
	if remoteAuthClientFactory == nil {
		remoteAuthClientFactory = func(endpoint string) RemoteAuthClient {
			return rpcclient.NewRemoteAuthRPCClient(endpoint)
		}
	}

	return &GatewayHTTPHandler{
		runtime:                   runtime,
		routingPipeline:           routingPipeline,
		authControl:               authControl,
		externalAuthClientFactory: externalAuthClientFactory,
		remoteAuthClientFactory:   remoteAuthClientFactory,
		businessClientFactory:     businessClientFactory,
	}
}

func (h *GatewayHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r == nil {
		h.writeError(w, http.StatusBadRequest, "request is required")
		return
	}

	ctx := r.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	spec, ok := LookupRouteSpec(r.Method, r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if spec.Kind == RouteKindHealth {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		return
	}
	if spec.Kind == RouteKindAuth && h.runtime.RunMode == modelsystem.RuntimeRunModeNoAuth {
		http.NotFound(w, r)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, fmt.Sprintf("read request body failed: %v", err))
		return
	}

	headers := normalizeHeaderMap(r.Header)
	switch spec.Kind {
	case RouteKindAuth:
		h.handleAuthRoute(ctx, w, r, spec, headers, bodyBytes)
	case RouteKindBusiness:
		h.handleBusinessRoute(ctx, w, r, spec, headers, bodyBytes)
	default:
		http.NotFound(w, r)
	}
}

func (h *GatewayHTTPHandler) handleAuthRoute(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	spec RouteSpec,
	headers map[string]string,
	bodyBytes []byte,
) {
	profile, err := h.resolveRouteProfile(ctx, spec, headers)
	if err != nil {
		h.writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if spec.ExpectedTargetService != "" && !strings.EqualFold(strings.TrimSpace(profile.TargetServiceName), spec.ExpectedTargetService) {
		h.writeError(w, http.StatusBadGateway, fmt.Sprintf("unexpected auth target service: %s", profile.TargetServiceName))
		return
	}
	if strings.TrimSpace(profile.TargetEndpoint) == "" {
		h.writeError(w, http.StatusBadGateway, "auth target endpoint is empty")
		return
	}

	client := h.externalAuthClientFactory(profile.TargetEndpoint)
	if client == nil {
		h.writeError(w, http.StatusBadGateway, "external auth client is not configured")
		return
	}

	switch spec.AuthRoute {
	case AuthRouteClientSignIn:
		h.handleClientSignIn(ctx, w, r, client, headers, bodyBytes)
	case AuthRouteClientRefreshSession:
		h.handleClientRefreshSession(ctx, w, r, client, headers, bodyBytes, profile)
	case AuthRouteEdgeBootstrapChallenge:
		h.handleEdgeBootstrapChallenge(ctx, w, r, client, headers, bodyBytes)
	case AuthRouteEdgeBootstrapAuthenticate:
		h.handleEdgeBootstrapAuthenticate(ctx, w, client, bodyBytes)
	case AuthRouteEdgeTokenRefresh:
		h.handleEdgeTokenRefresh(ctx, w, r, client, headers, bodyBytes)
	default:
		h.writeError(w, http.StatusNotFound, "auth route not found")
	}
}

func (h *GatewayHTTPHandler) handleBusinessRoute(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	spec RouteSpec,
	headers map[string]string,
	bodyBytes []byte,
) {
	payload, err := buildBusinessPayload(r, bodyBytes)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	profile, err := h.resolveRouteProfile(ctx, spec, headers)
	if err != nil {
		h.writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if spec.ExpectedTargetService != "" && !strings.EqualFold(strings.TrimSpace(profile.TargetServiceName), spec.ExpectedTargetService) {
		h.writeError(w, http.StatusBadGateway, fmt.Sprintf("unexpected business target service: %s", profile.TargetServiceName))
		return
	}
	if strings.TrimSpace(profile.TargetEndpoint) == "" {
		h.writeError(w, http.StatusBadGateway, "business target endpoint is empty")
		return
	}

	var authResult *authcontrolif.AuthControlResult
	if h.runtime.RunMode != modelsystem.RuntimeRunModeNoAuth && spec.authRequired {
		authInput, ok, parseErr := buildAuthorizationInput(headers, r)
		if parseErr != nil {
			h.writeError(w, http.StatusBadRequest, parseErr.Error())
			return
		}
		if !ok {
			h.writeError(w, http.StatusUnauthorized, "authorization header is required")
			return
		}
		if h.authControl == nil {
			h.writeError(w, http.StatusServiceUnavailable, "authcontrol is not configured")
			return
		}

		rateLimitInput := buildBusinessRateLimitInput(h.runtime, r, spec, headers, profile)
		authResult, err = h.authControl.Enforce(ctx, &authcontrolif.AuthControlRequest{
			Purpose:       authcontrolif.AuthControlPurposeInbound,
			Authorization: authInput,
			RateLimit:     rateLimitInput,
		})
		if err != nil {
			h.writeError(w, authErrorStatus(err), err.Error())
			return
		}
		if authResult == nil || authResult.RateLimitDecision == nil {
			h.writeError(w, http.StatusBadGateway, "authcontrol returned empty decision")
			return
		}
		if !authResult.RateLimitDecision.Allowed {
			reason := strings.TrimSpace(authResult.RateLimitDecision.Reason)
			if reason == "" {
				reason = "request is rate limited"
			}
			h.writeError(w, http.StatusTooManyRequests, reason)
			return
		}
	}

	businessClient := h.businessClientFactory(profile.TargetEndpoint)
	if businessClient == nil {
		h.writeError(w, http.StatusBadGateway, "business client is not configured")
		return
	}

	requestID, traceID := resolveRequestIDs(headers)
	businessRequest := &businessv1.BusinessForwardRequest{
		RouteKey:          spec.routeKey,
		Operation:         spec.operation,
		FlowCategory:      string(profile.FlowCategory),
		SourceService:     resolveGatewaySourceService(h.runtime),
		TargetServiceType: string(profile.TargetServiceType),
		TargetServiceName: profile.TargetServiceName,
		TargetEndpoint:    profile.TargetEndpoint,
		RequestId:         requestID,
		TraceId:           traceID,
		Headers:           normalizeForwardHeaders(headers),
		AuthContext:       buildBusinessAuthContext(authResult),
		Metadata:          buildBusinessMetadata(h.runtime, r, spec, profile, headers),
		Payload:           payload,
	}

	resp, err := businessClient.ForwardBusiness(ctx, businessRequest)
	if err != nil {
		h.writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if resp == nil {
		h.writeError(w, http.StatusBadGateway, "business forward response is empty")
		return
	}
	if !resp.GetAccepted() {
		reason := strings.TrimSpace(resp.GetErrorMessage())
		if reason == "" {
			reason = "business forward rejected"
		}
		h.writeError(w, http.StatusBadGateway, reason)
		return
	}

	if strings.TrimSpace(resp.GetPayload()) == "" {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(resp.GetPayload()))
}

func (h *GatewayHTTPHandler) handleClientSignIn(ctx context.Context, w http.ResponseWriter, r *http.Request, client ExternalAuthClient, headers map[string]string, bodyBytes []byte) {
	var reqBody appclientauthdto.ClientSignInRequest
	if err := json.Unmarshal(bodyBytes, &reqBody); err != nil {
		h.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid sign-in request: %v", err))
		return
	}
	if strings.TrimSpace(reqBody.Identifier) == "" {
		h.writeError(w, http.StatusBadRequest, "identifier is required")
		return
	}
	if strings.TrimSpace(reqBody.Password) == "" {
		h.writeError(w, http.StatusBadRequest, "password is required")
		return
	}

	result, err := client.AuthenticateUserPassword(ctx, &communicationif.UserPasswordAuthRequest{
		Username:  strings.TrimSpace(reqBody.Identifier),
		Password:  reqBody.Password,
		Audience:  strings.TrimSpace(headers["x-audience"]),
		Scopes:    parseCSVHeader(headers["x-scopes"]),
		ClientID:  firstNonEmpty(headers["x-client-id"], headers["x-downstream-principal"]),
		GatewayID: resolveGatewayID(h.runtime),
		SourceIP:  resolveSourceIP(headers, r),
		UserAgent: r.UserAgent(),
		RequestID: resolveRequestID(headers),
		TraceID:   resolveTraceID(headers),
	})
	if err != nil {
		h.writeError(w, http.StatusBadGateway, err.Error())
		return
	}

	response := mapClientAuthCredentialsResponse(result, nil, nil, time.Time{})
	h.writeJSON(w, http.StatusOK, response)
}

func (h *GatewayHTTPHandler) handleClientRefreshSession(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	client ExternalAuthClient,
	headers map[string]string,
	bodyBytes []byte,
	profile *commonif.RouteProfile,
) {
	var reqBody appclientauthdto.ClientRefreshSessionRequest
	if err := json.Unmarshal(bodyBytes, &reqBody); err != nil {
		h.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid refresh-session request: %v", err))
		return
	}
	if strings.TrimSpace(reqBody.RefreshToken) == "" {
		h.writeError(w, http.StatusBadRequest, "refresh_token is required")
		return
	}

	sessionID, err := parseUUIDField("session_id", reqBody.SessionID)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	remoteClient, err := h.resolveRemoteAuthClient(profile)
	if err != nil {
		h.writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	session, err := remoteClient.ValidateSession(ctx, &authif.SessionValidateRequest{
		SessionID:     sessionID,
		PrincipalID:   strings.TrimSpace(reqBody.PrincipalID),
		RequireActive: true,
		MinVersion:    0,
	})
	if err != nil {
		h.writeError(w, authErrorStatus(err), err.Error())
		return
	}
	if session == nil {
		h.writeError(w, http.StatusUnauthorized, "session not found")
		return
	}

	tokenBundle, err := client.ForwardRefreshTokenBundle(ctx, &authif.TokenRefreshRequest{
		RefreshToken: strings.TrimSpace(reqBody.RefreshToken),
		ClientID:     firstNonEmpty(headers["x-client-id"], session.ClientID, reqBody.PrincipalID),
		GatewayID:    resolveGatewayID(h.runtime),
		SourceIP:     resolveSourceIP(headers, r),
		UserAgent:    r.UserAgent(),
		RequestID:    resolveRequestID(headers),
		TraceID:      resolveTraceID(headers),
	})
	if err != nil {
		h.writeError(w, http.StatusBadGateway, err.Error())
		return
	}

	response := mapClientAuthCredentialsResponse(nil, session, tokenBundle, time.Now())
	if response.TokenID == "" {
		response.TokenID = strings.TrimSpace(reqBody.TokenID)
	}
	if response.TokenFamilyID == "" {
		response.TokenFamilyID = strings.TrimSpace(reqBody.TokenFamilyID)
	}
	if len(response.Scopes) == 0 {
		response.Scopes = append([]string(nil), reqBody.Scopes...)
	}
	h.writeJSON(w, http.StatusOK, response)
}

func (h *GatewayHTTPHandler) handleEdgeBootstrapChallenge(ctx context.Context, w http.ResponseWriter, r *http.Request, client ExternalAuthClient, headers map[string]string, bodyBytes []byte) {
	var reqBody edgeserverauthdto.BootstrapChallengeRequest
	if err := json.Unmarshal(bodyBytes, &reqBody); err != nil {
		h.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid bootstrap challenge request: %v", err))
		return
	}

	payload, err := client.ForwardBootstrapChallenge(ctx, &authmodel.ChallengeRequest{
		EntityType: authmodel.EntityDevice,
		EntityID:   strings.TrimSpace(reqBody.DeviceID),
		KeyID:      strings.TrimSpace(reqBody.KeyID),
		Audience:   strings.TrimSpace(reqBody.Audience),
		ClientID:   firstNonEmpty(headers["x-client-id"], headers["x-downstream-principal"]),
		GatewayID:  resolveGatewayID(h.runtime),
		SourceIP:   resolveSourceIP(headers, r),
		UserAgent:  r.UserAgent(),
		RequestID:  resolveRequestID(headers),
		TraceID:    resolveTraceID(headers),
	})
	if err != nil {
		h.writeError(w, http.StatusBadGateway, err.Error())
		return
	}

	response := mapBootstrapChallengeResponse(payload)
	h.writeJSON(w, http.StatusOK, response)
}

func (h *GatewayHTTPHandler) handleEdgeBootstrapAuthenticate(ctx context.Context, w http.ResponseWriter, client ExternalAuthClient, bodyBytes []byte) {
	var reqBody edgeserverauthdto.BootstrapAuthenticateRequest
	if err := json.Unmarshal(bodyBytes, &reqBody); err != nil {
		h.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid bootstrap authenticate request: %v", err))
		return
	}

	challenge, err := buildAuthChallengePayload(reqBody.Challenge)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	signed, err := buildSignedChallengeResponse(reqBody.Signed)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	result, err := client.ForwardBootstrapAuthenticate(ctx, &authmodel.BootstrapAuthRequest{
		Challenge:              challenge,
		Signed:                 signed,
		Scopes:                 append([]string(nil), reqBody.Scopes...),
		Role:                   strings.TrimSpace(reqBody.Role),
		RequireDownstreamToken: reqBody.RequireDownstreamToken,
	})
	if err != nil {
		h.writeError(w, http.StatusBadGateway, err.Error())
		return
	}

	response := mapEdgeAuthState(result)
	h.writeJSON(w, http.StatusOK, response)
}

func (h *GatewayHTTPHandler) handleEdgeTokenRefresh(ctx context.Context, w http.ResponseWriter, r *http.Request, client ExternalAuthClient, headers map[string]string, bodyBytes []byte) {
	var reqBody edgeserverauthdto.RefreshTokenRequest
	if err := json.Unmarshal(bodyBytes, &reqBody); err != nil {
		h.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid token refresh request: %v", err))
		return
	}

	tokenBundle, err := client.ForwardRefreshTokenBundle(ctx, &authif.TokenRefreshRequest{
		RefreshToken: strings.TrimSpace(reqBody.RefreshToken),
		ClientID:     strings.TrimSpace(reqBody.ClientID),
		GatewayID:    resolveGatewayID(h.runtime),
		SourceIP:     resolveSourceIP(headers, r),
		UserAgent:    r.UserAgent(),
		RequestID:    resolveRequestID(headers),
		TraceID:      resolveTraceID(headers),
	})
	if err != nil {
		h.writeError(w, http.StatusBadGateway, err.Error())
		return
	}

	response := mapEdgeTokenBundle(tokenBundle, nil, nil)
	h.writeJSON(w, http.StatusOK, response)
}

func (h *GatewayHTTPHandler) resolveRouteProfile(
	ctx context.Context,
	spec RouteSpec,
	headers map[string]string,
) (*commonif.RouteProfile, error) {
	if h.routingPipeline == nil {
		return nil, &modelsystem.ErrResolverDependenciesRequired
	}

	flow := &commonif.FlowRouteInput{
		RouteKey:      spec.routeKey,
		Transport:     "http",
		Method:        spec.Method,
		Path:          spec.path,
		SourceService: resolveGatewaySourceService(h.runtime),
		Metadata: map[string]string{
			"http_route_kind": spec.operation,
			"http_path":       spec.path,
			"http_method":     spec.Method,
			"gateway_id":      resolveGatewayID(h.runtime),
		},
	}
	if query := strings.TrimSpace(headers["x-http-query"]); query != "" {
		flow.Metadata["http_query"] = query
	}

	profile, err := h.routingPipeline.ResolveRouteProfile(ctx, flow)
	if err != nil {
		return nil, err
	}
	if profile == nil {
		return nil, &modelsystem.ErrRouteRuleNotFound
	}
	return profile, nil
}

func (h *GatewayHTTPHandler) resolveRemoteAuthClient(profile *commonif.RouteProfile) (RemoteAuthClient, error) {
	if profile == nil {
		return nil, &modelsystem.ErrRouteRuleNotFound
	}
	if strings.TrimSpace(profile.TargetEndpoint) == "" {
		return nil, &modelsystem.ErrEndpointRequired
	}
	if h.remoteAuthClientFactory == nil {
		return nil, &modelsystem.ErrAuthAuthorityChannelDependenciesRequired
	}
	client := h.remoteAuthClientFactory(profile.TargetEndpoint)
	if client == nil {
		return nil, &modelsystem.ErrAuthAuthorityChannelDependenciesRequired
	}
	return client, nil
}

func buildBusinessPayload(r *http.Request, bodyBytes []byte) (string, error) {
	if r == nil {
		return "", &modelsystem.ErrForwardingRequestInvalid
	}
	if r.Method == http.MethodGet {
		if encoded, err := encodeQueryPayload(r.URL.Query()); err == nil && strings.TrimSpace(encoded) != "" {
			return encoded, nil
		}
	}

	payload := strings.TrimSpace(string(bodyBytes))
	if payload == "" {
		if encoded, err := encodeQueryPayload(r.URL.Query()); err == nil {
			return encoded, nil
		}
	}
	return payload, nil
}

func encodeQueryPayload(values url.Values) (string, error) {
	if len(values) == 0 {
		return "", nil
	}

	encoded := make(map[string]any, len(values))
	for key, items := range values {
		if len(items) == 0 {
			continue
		}
		if len(items) == 1 {
			encoded[key] = items[0]
			continue
		}
		cloned := append([]string(nil), items...)
		encoded[key] = cloned
	}
	if len(encoded) == 0 {
		return "", nil
	}

	bytes, err := json.Marshal(encoded)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func buildAuthorizationInput(headers map[string]string, r *http.Request) (*authcontrolif.AuthorizationInput, bool, error) {
	rawToken := ""
	if r != nil {
		rawToken = extractBearerToken(r.Header.Get("Authorization"))
	}
	sessionID, err := parseUUIDMaybe(firstNonEmpty(headers[authmodel.HeaderDownstreamSessionID], headerValue(r, authmodel.HeaderDownstreamSessionID)))
	if err != nil {
		return nil, false, err
	}
	principalID := firstNonEmpty(headers[authmodel.HeaderDownstreamPrincipal], headerValue(r, authmodel.HeaderDownstreamPrincipal))
	if _, err := parseUUIDMaybe(firstNonEmpty(headers[authmodel.HeaderDownstreamTokenID], headerValue(r, authmodel.HeaderDownstreamTokenID))); err != nil {
		return nil, false, err
	}

	if rawToken == "" && sessionID == uuid.Nil {
		return nil, false, nil
	}

	input := &authcontrolif.AuthorizationInput{
		RawToken:            rawToken,
		SessionID:           sessionID,
		PrincipalID:         principalID,
		RequireActive:       true,
		ExpectedTokenTypes:  parseTokenTypes(headers["x-token-type"]),
		ExpectedAudience:    strings.TrimSpace(headers["x-audience"]),
		RequireScopes:       parseCSVHeader(headers["x-scopes"]),
		AllowExpiredSkewSec: 0,
	}
	if input.ExpectedAudience == "" {
		input.ExpectedAudience = strings.TrimSpace(r.Host)
	}
	return input, true, nil
}

func buildBusinessRateLimitInput(
	runtime modelsystem.RuntimeConfig,
	r *http.Request,
	spec RouteSpec,
	headers map[string]string,
	profile *commonif.RouteProfile,
) *authcontrolif.RateLimitInput {
	tags := map[string]string{
		"http_path":       spec.path,
		"http_method":     spec.Method,
		"http_route_kind": spec.operation,
		"target_service":  profile.TargetServiceName,
		"target_endpoint": profile.TargetEndpoint,
	}
	for key, value := range headers {
		if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
			continue
		}
		tags["header."+key] = value
	}

	return &authcontrolif.RateLimitInput{
		Scope:         authmodel.RateLimitScopeAuth,
		Transport:     "http",
		Module:        profile.TargetServiceName,
		Action:        spec.operation,
		Route:         spec.routeKey,
		Method:        spec.Method,
		SourceIP:      resolveSourceIP(headers, r),
		GatewayID:     resolveGatewayID(runtime),
		ClientID:      firstNonEmpty(headers["x-client-id"], headers[authmodel.HeaderDownstreamPrincipal]),
		SourceService: resolveGatewaySourceService(runtime),
		TargetService: profile.TargetServiceName,
		Headers:       copyStringMap(headers),
		Tags:          tags,
		Identity:      nil,
	}
}

func buildBusinessAuthContext(result *authcontrolif.AuthControlResult) *businessv1.BusinessAuthContext {
	if result == nil || result.Identity == nil {
		return nil
	}

	identity := result.Identity
	principalID := strings.TrimSpace(identity.PrincipalID)
	if principalID == "" {
		principalID = strings.TrimSpace(identity.Principal.PrincipalID())
	}

	return &businessv1.BusinessAuthContext{
		PrincipalId:   principalID,
		SessionId:     uuidToString(identity.SessionID),
		TokenId:       uuidToString(identity.TokenID),
		TokenFamilyId: uuidToString(identity.TokenFamilyID),
		TokenType:     string(identity.TokenType),
		Scopes:        append([]string(nil), identity.Scopes...),
		AuthMethod:    string(identity.AuthMethod),
		ClientId:      strings.TrimSpace(identity.ClientID),
		GatewayId:     strings.TrimSpace(identity.GatewayID),
		SourceIp:      strings.TrimSpace(identity.SourceIP),
		UserAgent:     strings.TrimSpace(identity.UserAgent),
		IssuedAtMs:    identity.IssuedAt.UnixMilli(),
		ExpiresAtMs:   identity.ExpiresAt.UnixMilli(),
	}
}

func buildBusinessMetadata(
	runtime modelsystem.RuntimeConfig,
	r *http.Request,
	spec RouteSpec,
	profile *commonif.RouteProfile,
	headers map[string]string,
) map[string]string {
	metadata := map[string]string{
		"http_path":       spec.path,
		"http_method":     spec.Method,
		"http_route_kind": spec.operation,
		"route_key":       spec.routeKey,
		"flow_category":   string(profile.FlowCategory),
		"target_service":  profile.TargetServiceName,
		"target_endpoint": profile.TargetEndpoint,
		"gateway_id":      resolveGatewayID(runtime),
	}
	if r != nil && r.URL != nil {
		metadata["http_query"] = strings.TrimSpace(r.URL.RawQuery)
	}
	for key, value := range headers {
		if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
			continue
		}
		metadata["header."+key] = value
	}
	return metadata
}

func mapClientAuthCredentialsResponse(userResult *communicationif.UserPasswordAuthResult, session *authmodel.Session, tokenBundle *authmodel.TokenBundle, issuedAt time.Time) appclientauthdto.ClientAuthCredentialsResponse {
	response := appclientauthdto.ClientAuthCredentialsResponse{Persisted: false}
	if userResult != nil {
		response.AccessToken = tokenRaw(userResult.Tokens.AccessToken)
		response.RefreshToken = tokenRaw(userResult.Tokens.RefreshToken)
		response.DownstreamToken = tokenRaw(userResult.Tokens.DownstreamToken)
		response.TokenType = tokenTypeFromBundle(&userResult.Tokens)
		response.IssuedAtMs = userResult.IssuedAt.UnixMilli()
		if !userResult.ExpiresAt.IsZero() {
			response.AccessExpiresAtMs = userResult.ExpiresAt.UnixMilli()
		}
		if identity := userResult.Identity; identity != nil {
			response.SessionID = uuidToString(identity.SessionID)
			response.TokenID = uuidToString(identity.TokenID)
			response.PrincipalID = strings.TrimSpace(identity.PrincipalID)
			if response.PrincipalID == "" {
				response.PrincipalID = strings.TrimSpace(identity.Principal.PrincipalID())
			}
			response.TokenFamilyID = uuidToString(identity.TokenFamilyID)
			response.Scopes = append([]string(nil), identity.Scopes...)
		}
	}
	if session != nil {
		if response.SessionID == "" {
			response.SessionID = uuidToString(session.ID)
		}
		if response.PrincipalID == "" {
			response.PrincipalID = strings.TrimSpace(session.PrincipalID)
		}
		if response.TokenFamilyID == "" {
			response.TokenFamilyID = uuidToString(session.TokenFamilyID)
		}
		if len(response.Scopes) == 0 {
			response.Scopes = append([]string(nil), session.ScopeSnapshot...)
		}
	}
	if tokenBundle != nil {
		if response.AccessToken == "" {
			response.AccessToken = tokenRaw(tokenBundle.AccessToken)
		}
		if response.RefreshToken == "" {
			response.RefreshToken = tokenRaw(tokenBundle.RefreshToken)
		}
		if response.DownstreamToken == "" {
			response.DownstreamToken = tokenRaw(tokenBundle.DownstreamToken)
		}
		if response.TokenType == "" {
			response.TokenType = tokenTypeFromBundle(tokenBundle)
		}
		if response.IssuedAtMs == 0 {
			response.IssuedAtMs = issuedAt.UnixMilli()
		}
		if response.AccessExpiresAtMs == 0 {
			response.AccessExpiresAtMs = expiresAtFromIssued(issuedAt, tokenBundle.AccessToken)
		}
		if response.RefreshExpiresAtMs == 0 {
			response.RefreshExpiresAtMs = expiresAtFromIssued(issuedAt, tokenBundle.RefreshToken)
		}
	}
	if response.AccessExpiresAtMs == 0 && !issuedAt.IsZero() {
		response.AccessExpiresAtMs = issuedAt.Add(15 * time.Minute).UnixMilli()
	}
	if response.RefreshExpiresAtMs == 0 && !issuedAt.IsZero() {
		response.RefreshExpiresAtMs = issuedAt.Add(24 * time.Hour).UnixMilli()
	}
	if response.TokenType == "" {
		response.TokenType = string(authmodel.TokenAccess)
	}
	return response
}

func mapBootstrapChallengeResponse(payload *authmodel.ChallengePayload) edgeserverauthdto.BootstrapChallenge {
	if payload == nil {
		return edgeserverauthdto.BootstrapChallenge{}
	}
	return edgeserverauthdto.BootstrapChallenge{
		ChallengeID: payload.ChallengeID.String(),
		Nonce:       strings.TrimSpace(payload.Nonce),
		Issuer:      strings.TrimSpace(payload.Issuer),
		Audience:    strings.TrimSpace(payload.Audience),
		IssuedAtMs:  payload.IssuedAt.UnixMilli(),
		ExpiresAtMs: payload.ExpiresAt.UnixMilli(),
		EntityType:  string(payload.EntityType),
		EntityID:    strings.TrimSpace(payload.EntityID),
		KeyID:       strings.TrimSpace(payload.KeyID),
	}
}

func mapEdgeAuthState(result *authmodel.BootstrapAuthResult) edgeserverauthdto.EdgeAuthState {
	state := edgeserverauthdto.EdgeAuthState{}
	if result == nil {
		return state
	}
	state.Stage = string(result.Stage)
	state.Session = mapEdgeSession(result.Session)
	state.Tokens = mapEdgeTokenBundle(&result.Tokens, result.Identity, result.Session)
	return state
}

func mapEdgeSession(session *authmodel.Session) *edgeserverauthdto.EdgeSession {
	if session == nil {
		return nil
	}
	deviceID := strings.TrimSpace(session.EntityID)
	if deviceID == "" {
		deviceID = strings.TrimSpace(session.Principal.EntityID)
	}
	return &edgeserverauthdto.EdgeSession{
		SessionID:        uuidToString(session.ID),
		PrincipalID:      strings.TrimSpace(session.PrincipalID),
		DeviceID:         deviceID,
		Status:           string(session.Status),
		IssuedAtMs:       session.CreatedAt.UnixMilli(),
		ExpiresAtMs:      session.ExpiresAt.UnixMilli(),
		TokenFamilyID:    uuidToString(session.TokenFamilyID),
		LastVerifiedAtMs: session.LastVerifiedAt.UnixMilli(),
	}
}

func mapEdgeTokenBundle(
	bundle *authmodel.TokenBundle,
	identity *authmodel.IdentityContext,
	session *authmodel.Session,
) *edgeserverauthdto.EdgeTokenBundle {
	if bundle == nil {
		return nil
	}
	if bundle.AccessToken == nil && bundle.RefreshToken == nil && bundle.DownstreamToken == nil {
		return nil
	}
	issuedAt := time.Now().UTC()
	if identity != nil && !identity.IssuedAt.IsZero() {
		issuedAt = identity.IssuedAt
	} else if session != nil && !session.CreatedAt.IsZero() {
		issuedAt = session.CreatedAt
	}

	return &edgeserverauthdto.EdgeTokenBundle{
		AccessToken:  mapEdgeToken(bundle.AccessToken, identity, session, issuedAt, authmodel.TokenAccess),
		RefreshToken: mapEdgeToken(bundle.RefreshToken, identity, session, issuedAt, authmodel.TokenRefresh),
	}
}

func mapEdgeToken(
	token *authmodel.IssuedToken,
	identity *authmodel.IdentityContext,
	session *authmodel.Session,
	issuedAt time.Time,
	fallbackType authmodel.TokenType,
) *edgeserverauthdto.EdgeToken {
	if token == nil {
		return nil
	}

	tokenType := string(token.Type)
	if tokenType == "" {
		tokenType = string(fallbackType)
	}
	edgeToken := &edgeserverauthdto.EdgeToken{
		Raw:         strings.TrimSpace(token.Raw),
		TokenType:   tokenType,
		IssuedAtMs:  issuedAt.UnixMilli(),
		ExpiresAtMs: expiresAtFromIssued(issuedAt, token),
	}
	if identity != nil {
		edgeToken.TokenID = uuidToString(identity.TokenID)
		edgeToken.FamilyID = uuidToString(identity.TokenFamilyID)
		edgeToken.SessionID = uuidToString(identity.SessionID)
		edgeToken.Scopes = append([]string(nil), identity.Scopes...)
		edgeToken.Role = strings.TrimSpace(identity.Role)
	}
	if edgeToken.TokenID == "" && session != nil {
		edgeToken.SessionID = uuidToString(session.ID)
		edgeToken.FamilyID = uuidToString(session.TokenFamilyID)
		if len(edgeToken.Scopes) == 0 {
			edgeToken.Scopes = append([]string(nil), session.ScopeSnapshot...)
		}
		if edgeToken.Role == "" {
			edgeToken.Role = strings.TrimSpace(session.RoleSnapshot)
		}
	}
	return edgeToken
}

func tokenRaw(token *authmodel.IssuedToken) string {
	if token == nil {
		return ""
	}
	return strings.TrimSpace(token.Raw)
}

func tokenTypeFromBundle(bundle *authmodel.TokenBundle) string {
	if bundle == nil {
		return ""
	}
	if bundle.AccessToken != nil && strings.TrimSpace(string(bundle.AccessToken.Type)) != "" {
		return string(bundle.AccessToken.Type)
	}
	if bundle.RefreshToken != nil && strings.TrimSpace(string(bundle.RefreshToken.Type)) != "" {
		return string(bundle.RefreshToken.Type)
	}
	if bundle.DownstreamToken != nil && strings.TrimSpace(string(bundle.DownstreamToken.Type)) != "" {
		return string(bundle.DownstreamToken.Type)
	}
	return ""
}

func expiresAtFromIssued(issuedAt time.Time, token *authmodel.IssuedToken) int64 {
	if token == nil || token.TTLSec <= 0 {
		return 0
	}
	base := issuedAt
	if base.IsZero() {
		base = time.Now().UTC()
	}
	return base.Add(time.Duration(token.TTLSec) * time.Second).UnixMilli()
}

func buildAuthChallengePayload(raw edgeserverauthdto.BootstrapChallenge) (authmodel.ChallengePayload, error) {
	challengeID, err := parseUUIDField("challenge_id", raw.ChallengeID)
	if err != nil {
		return authmodel.ChallengePayload{}, err
	}

	return authmodel.ChallengePayload{
		ChallengeID: challengeID,
		Issuer:      strings.TrimSpace(raw.Issuer),
		Audience:    strings.TrimSpace(raw.Audience),
		EntityType:  authmodel.EntityType(strings.TrimSpace(raw.EntityType)),
		EntityID:    strings.TrimSpace(raw.EntityID),
		KeyID:       strings.TrimSpace(raw.KeyID),
		Nonce:       strings.TrimSpace(raw.Nonce),
		IssuedAt:    unixMillisToTime(raw.IssuedAtMs),
		ExpiresAt:   unixMillisToTime(raw.ExpiresAtMs),
	}, nil
}

func buildSignedChallengeResponse(raw edgeserverauthdto.SignedBootstrapProof) (authmodel.SignedChallengeResponse, error) {
	challengeID, err := parseUUIDField("signed.challenge_id", raw.ChallengeID)
	if err != nil {
		return authmodel.SignedChallengeResponse{}, err
	}

	return authmodel.SignedChallengeResponse{
		ChallengeID:        challengeID,
		KeyID:              strings.TrimSpace(raw.KeyID),
		SignatureAlgorithm: commsecmodel.SignatureAlgorithm(strings.TrimSpace(raw.SignatureAlgorithm)),
		Signature:          strings.TrimSpace(raw.Signature),
		SignedAt:           unixMillisToTime(raw.SignedAtMs),
	}, nil
}

func (h *GatewayHTTPHandler) writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if payload == nil {
		return
	}
	data, err := json.Marshal(payload)
	if err != nil {
		_, _ = w.Write([]byte(fmt.Sprintf(`{"error":"marshal response failed: %v"}`, err)))
		return
	}
	_, _ = w.Write(data)
}

func (h *GatewayHTTPHandler) writeError(w http.ResponseWriter, status int, message string) {
	if status <= 0 {
		status = http.StatusInternalServerError
	}
	h.writeJSON(w, status, map[string]string{"error": strings.TrimSpace(message)})
}

func authErrorStatus(err error) int {
	if err == nil {
		return http.StatusBadGateway
	}
	if errors.Is(err, &modelsystem.ErrInvalidUserCredentials) {
		return http.StatusUnauthorized
	}
	if errors.Is(err, &modelsystem.ErrSessionNotFound) {
		return http.StatusUnauthorized
	}
	if errors.Is(err, &modelsystem.ErrSessionNotActive) {
		return http.StatusForbidden
	}
	if errors.Is(err, &modelsystem.ErrRequestRateLimited) {
		return http.StatusTooManyRequests
	}
	return http.StatusBadGateway
}

func parseUUIDField(fieldName string, raw string) (uuid.UUID, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return uuid.Nil, fmt.Errorf("%s is required", fieldName)
	}
	parsed, err := uuid.Parse(trimmed)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid %s: %w", fieldName, err)
	}
	return parsed, nil
}

func parseUUIDMaybe(raw string) (uuid.UUID, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return uuid.Nil, nil
	}
	parsed, err := uuid.Parse(trimmed)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid uuid: %w", err)
	}
	return parsed, nil
}

func parseTokenTypes(raw string) []authmodel.TokenType {
	items := parseCSVHeader(raw)
	if len(items) == 0 {
		return nil
	}

	out := make([]authmodel.TokenType, 0, len(items))
	for _, item := range items {
		resolved := authmodel.TokenType(strings.TrimSpace(item))
		if resolved == "" {
			continue
		}
		out = append(out, resolved)
	}
	return out
}

func parseCSVHeader(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == ' '
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

func extractBearerToken(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(raw), "bearer ") {
		return strings.TrimSpace(raw[len("bearer "):])
	}
	return raw
}

func normalizeHeaderMap(source http.Header) map[string]string {
	if len(source) == 0 {
		return map[string]string{}
	}

	out := make(map[string]string, len(source))
	for key, values := range source {
		trimmedKey := strings.ToLower(strings.TrimSpace(key))
		if trimmedKey == "" || trimmedKey == "authorization" || trimmedKey == "cookie" {
			continue
		}
		cleaned := make([]string, 0, len(values))
		for _, value := range values {
			trimmedValue := strings.TrimSpace(value)
			if trimmedValue == "" {
				continue
			}
			cleaned = append(cleaned, trimmedValue)
		}
		if len(cleaned) == 0 {
			continue
		}
		out[trimmedKey] = strings.Join(cleaned, ",")
	}
	return out
}

func normalizeForwardHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return map[string]string{}
	}

	out := make(map[string]string, len(headers))
	for key, value := range headers {
		trimmedKey := strings.ToLower(strings.TrimSpace(key))
		trimmedValue := strings.TrimSpace(value)
		if trimmedKey == "" || trimmedValue == "" || trimmedKey == "authorization" || trimmedKey == "cookie" {
			continue
		}
		out[trimmedKey] = trimmedValue
	}
	return out
}

func copyStringMap(source map[string]string) map[string]string {
	if len(source) == 0 {
		return map[string]string{}
	}

	out := make(map[string]string, len(source))
	for key, value := range source {
		out[key] = value
	}
	return out
}

func resolveGatewayID(runtime modelsystem.RuntimeConfig) string {
	if trimmed := strings.TrimSpace(runtime.InstanceID); trimmed != "" {
		return trimmed
	}
	if trimmed := strings.TrimSpace(runtime.ServiceName); trimmed != "" {
		return trimmed
	}
	return "gateway"
}

func resolveGatewaySourceService(runtime modelsystem.RuntimeConfig) string {
	if trimmed := strings.TrimSpace(runtime.ServiceName); trimmed != "" {
		return trimmed
	}
	return "gateway"
}

func resolveRequestID(headers map[string]string) string {
	if trimmed := strings.TrimSpace(headers["x-request-id"]); trimmed != "" {
		return trimmed
	}
	return uuid.New().String()
}

func resolveTraceID(headers map[string]string) string {
	if trimmed := strings.TrimSpace(headers["x-trace-id"]); trimmed != "" {
		return trimmed
	}
	return uuid.New().String()
}

func resolveRequestIDs(headers map[string]string) (string, string) {
	return resolveRequestID(headers), resolveTraceID(headers)
}

func resolveSourceIP(headers map[string]string, r *http.Request) string {
	if trimmed := strings.TrimSpace(headers["x-source-ip"]); trimmed != "" {
		return trimmed
	}
	if trimmed := strings.TrimSpace(headers["x-real-ip"]); trimmed != "" {
		return trimmed
	}
	if r != nil {
		if host, _, ok := strings.Cut(r.RemoteAddr, ":"); ok {
			if trimmed := strings.TrimSpace(host); trimmed != "" {
				return trimmed
			}
		}
		if trimmed := strings.TrimSpace(r.RemoteAddr); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func headerValue(r *http.Request, key string) string {
	if r == nil {
		return ""
	}
	return strings.TrimSpace(r.Header.Get(key))
}

func unixMillisToTime(value int64) time.Time {
	if value <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(value).UTC()
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func uuidToString(value uuid.UUID) string {
	if value == uuid.Nil {
		return ""
	}
	return value.String()
}
