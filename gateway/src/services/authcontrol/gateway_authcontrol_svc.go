package authcontrolsvc

import (
	"context"
	"fmt"
	"strings"

	authif "gateway/src/iface/auth"
	authcontrolif "gateway/src/iface/authcontrol"
	commonif "gateway/src/iface/common"
	authmodel "gateway/src/models/auth"
	modelsystem "gateway/src/models/system"
	rpcclient "gateway/src/services/communication/rpc_client"

	"github.com/google/uuid"
)

const (
	defaultAuthAuthorityServiceName = "certification_server"

	remoteAuthVerifyRouteKey      = "auth.remote.verify.token"
	remoteSessionValidateRouteKey = "auth.remote.validate.session"

	remoteAuthVerifyMethodPath      = "/bms.auth.v1.AuthAuthorityRemoteAuthService/VerifyToken"
	remoteSessionValidateMethodPath = "/bms.auth.v1.AuthAuthorityRemoteAuthService/ValidateSession"
)

type rateLimiter interface {
	Decide(ctx context.Context, descriptor *authmodel.RateLimitDescriptor) (*authmodel.RateLimitDecision, error)
}

type IRemoteAuthClient interface {
	VerifyToken(ctx context.Context, req *authif.TokenVerifyRequest) (*authmodel.TokenVerificationResult, error)
	ValidateSession(ctx context.Context, req *authif.SessionValidateRequest) (*authmodel.Session, error)
}

type RemoteAuthClientFactory func(endpoint string) IRemoteAuthClient

var _ authcontrolif.IGatewayAuthControl = (*GatewayAuthControlService)(nil)

// GatewayAuthControlService 为 gateway 提供统一认证消费与限流控制。
type GatewayAuthControlService struct {
	runtimeMode modelsystem.RuntimeRunMode

	serviceResolver commonif.IServiceResolver
	rateLimiter     rateLimiter
	clientFactory   RemoteAuthClientFactory
}

// NewGatewayAuthControlService 构造 gateway 的认证控制门面。
func NewGatewayAuthControlService(
	runtimeMode modelsystem.RuntimeRunMode,
	serviceResolver commonif.IServiceResolver,
	rateLimiter rateLimiter,
	clientFactory RemoteAuthClientFactory,
) authcontrolif.IGatewayAuthControl {
	if rateLimiter == nil {
		rateLimiter = NewLocalRateLimiterService()
	}
	if clientFactory == nil {
		clientFactory = func(endpoint string) IRemoteAuthClient {
			return rpcclient.NewRemoteAuthRPCClient(endpoint)
		}
	}

	return &GatewayAuthControlService{
		runtimeMode:     runtimeMode,
		serviceResolver: serviceResolver,
		rateLimiter:     rateLimiter,
		clientFactory:   clientFactory,
	}
}

// Enforce 执行统一认证校验与限流决策。
func (s *GatewayAuthControlService) Enforce(
	ctx context.Context,
	req *authcontrolif.AuthControlRequest,
) (*authcontrolif.AuthControlResult, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if req == nil || req.RateLimit == nil {
		return nil, &modelsystem.ErrRateLimitRequestInvalid
	}
	if s.runtimeMode == modelsystem.RuntimeRunModeNoAuth {
		return &authcontrolif.AuthControlResult{RateLimitDecision: disabledRateLimitDecision()}, nil
	}

	rateLimitInput := cloneRateLimitInput(req.RateLimit)
	applyRateLimitDefaults(req.Purpose, rateLimitInput)

	identity, session, tokenVerification, err := s.resolveAuthorization(ctx, rateLimitInput, req.Authorization)
	if err != nil {
		return nil, err
	}
	if identity == nil && rateLimitInput.Identity != nil {
		identity = cloneIdentity(rateLimitInput.Identity)
	}
	if identity != nil {
		rateLimitInput.Identity = identity
	}

	descriptor, err := buildRateLimitDescriptor(rateLimitInput)
	if err != nil {
		return nil, err
	}

	decision, err := s.rateLimiter.Decide(ctx, descriptor)
	if err != nil {
		return nil, err
	}

	return &authcontrolif.AuthControlResult{
		Identity:          identity,
		Session:           session,
		TokenVerification: tokenVerification,
		RateLimitDecision: decision,
	}, nil
}

func (s *GatewayAuthControlService) resolveAuthorization(
	ctx context.Context,
	rateLimitInput *authcontrolif.RateLimitInput,
	authInput *authcontrolif.AuthorizationInput,
) (*authmodel.IdentityContext, *authmodel.Session, *authmodel.TokenVerificationResult, error) {
	if authInput == nil {
		return nil, nil, nil, nil
	}

	shouldValidateToken := strings.TrimSpace(authInput.RawToken) != ""
	shouldValidateSession := authInput.SessionID != uuid.Nil
	if !shouldValidateToken && !shouldValidateSession {
		return nil, nil, nil, nil
	}

	routeKey := remoteAuthVerifyRouteKey
	methodPath := remoteAuthVerifyMethodPath
	if !shouldValidateToken && shouldValidateSession {
		routeKey = remoteSessionValidateRouteKey
		methodPath = remoteSessionValidateMethodPath
	}

	client, err := s.resolveRemoteAuthClient(ctx, rateLimitInput, routeKey, methodPath)
	if err != nil {
		return nil, nil, nil, err
	}

	var identity *authmodel.IdentityContext
	var session *authmodel.Session
	var tokenVerification *authmodel.TokenVerificationResult

	if shouldValidateToken {
		tokenVerification, err = client.VerifyToken(ctx, &authif.TokenVerifyRequest{
			RawToken:            strings.TrimSpace(authInput.RawToken),
			ExpectedTypes:       append([]authmodel.TokenType(nil), authInput.ExpectedTokenTypes...),
			ExpectedAudience:    strings.TrimSpace(authInput.ExpectedAudience),
			RequireScopes:       append([]string(nil), authInput.RequireScopes...),
			SourceService:       strings.TrimSpace(rateLimitInput.SourceService),
			TargetService:       strings.TrimSpace(rateLimitInput.TargetService),
			AllowExpiredSkewSec: authInput.AllowExpiredSkewSec,
		})
		if err != nil {
			return nil, nil, nil, err
		}
		if tokenVerification != nil {
			identity = mergeIdentityFromToken(tokenVerification.Identity, tokenVerification.Token)
			if !tokenVerification.Valid {
				reason := strings.TrimSpace(tokenVerification.FailureReason)
				if reason == "" {
					reason = "token verification rejected"
				}
				return nil, nil, tokenVerification, fmt.Errorf("%w: %s", &modelsystem.ErrInvalidUserCredentials, reason)
			}
		}
	}

	if shouldValidateSession {
		session, err = client.ValidateSession(ctx, &authif.SessionValidateRequest{
			SessionID:     authInput.SessionID,
			PrincipalID:   strings.TrimSpace(authInput.PrincipalID),
			RequireActive: authInput.RequireActive,
			MinVersion:    authInput.MinVersion,
		})
		if err != nil {
			return nil, nil, tokenVerification, err
		}
		if session == nil {
			return nil, nil, tokenVerification, &modelsystem.ErrSessionNotFound
		}
		if authInput.RequireActive && session.Status != authmodel.SessionActive {
			return nil, nil, tokenVerification, &modelsystem.ErrSessionNotActive
		}
		if identity == nil {
			identity = identityFromSession(session)
		}
	}

	return identity, session, tokenVerification, nil
}

func (s *GatewayAuthControlService) resolveRemoteAuthClient(
	ctx context.Context,
	rateLimitInput *authcontrolif.RateLimitInput,
	routeKey string,
	methodPath string,
) (IRemoteAuthClient, error) {
	if s.serviceResolver == nil {
		return nil, &modelsystem.ErrResolverDependenciesRequired
	}

	flow := &commonif.FlowRouteInput{
		RouteKey:          routeKey,
		Transport:         "grpc",
		Method:            "POST",
		Path:              methodPath,
		SourceService:     resolveSourceService(rateLimitInput),
		TargetServiceHint: defaultAuthAuthorityServiceName,
		Metadata: map[string]string{
			"trusted_internal_call": "true",
		},
	}

	target, err := s.serviceResolver.ResolveTargetInstance(ctx, flow)
	if err != nil {
		return nil, err
	}
	endpoint := ""
	if target != nil {
		endpoint = strings.TrimSpace(target.Endpoint)
	}
	if endpoint == "" {
		return nil, &modelsystem.ErrEndpointRequired
	}

	client := s.clientFactory(endpoint)
	if client == nil {
		return nil, &modelsystem.ErrAuthAuthorityChannelDependenciesRequired
	}
	return client, nil
}

func buildRateLimitDescriptor(input *authcontrolif.RateLimitInput) (*authmodel.RateLimitDescriptor, error) {
	if input == nil {
		return nil, &modelsystem.ErrRateLimitRequestInvalid
	}

	descriptor := &authmodel.RateLimitDescriptor{
		Scope:         input.Scope,
		Transport:     input.Transport,
		Module:        input.Module,
		Action:        input.Action,
		Route:         input.Route,
		Method:        input.Method,
		SourceIP:      input.SourceIP,
		GatewayID:     input.GatewayID,
		ClientID:      input.ClientID,
		SourceService: input.SourceService,
		TargetService: input.TargetService,
		Tags:          copyStringMap(input.Tags),
	}

	if descriptor.Tags == nil {
		descriptor.Tags = map[string]string{}
	}

	if input.Identity != nil {
		principal := input.Identity.Principal
		if principal.EntityType == "" && strings.TrimSpace(string(input.Identity.EntityType)) != "" {
			principal.EntityType = input.Identity.EntityType
		}
		if principal.EntityID == "" && strings.TrimSpace(input.Identity.EntityID) != "" {
			principal.EntityID = input.Identity.EntityID
		}

		descriptor.Authenticated = true
		descriptor.EntityType = input.Identity.EntityType
		descriptor.EntityID = input.Identity.EntityID
		descriptor.PrincipalID = strings.TrimSpace(input.Identity.PrincipalID)
		if descriptor.PrincipalID == "" {
			descriptor.PrincipalID = strings.TrimSpace(principal.PrincipalID())
		}
		descriptor.SessionID = input.Identity.SessionID.String()
		descriptor.TokenID = input.Identity.TokenID.String()
		descriptor.TokenType = input.Identity.TokenType
		descriptor.Scopes = append([]string(nil), input.Identity.Scopes...)
	}

	return descriptor, nil
}

func applyRateLimitDefaults(purpose authcontrolif.AuthControlPurpose, input *authcontrolif.RateLimitInput) {
	if input == nil {
		return
	}

	if strings.TrimSpace(input.Transport) == "" {
		switch purpose {
		case authcontrolif.AuthControlPurposeOutbound:
			input.Transport = "grpc"
		default:
			input.Transport = "http"
		}
	}
	if strings.TrimSpace(input.Module) == "" {
		input.Module = strings.TrimSpace(input.TargetService)
	}
	if strings.TrimSpace(input.Action) == "" {
		input.Action = strings.TrimSpace(input.Route)
	}
	if strings.TrimSpace(input.TargetService) == "" {
		input.TargetService = strings.TrimSpace(input.Module)
	}
	if input.Headers == nil {
		input.Headers = map[string]string{}
	}
	if input.Tags == nil {
		input.Tags = map[string]string{}
	}
	if input.Scope == "" {
		switch purpose {
		case authcontrolif.AuthControlPurposeOutbound:
			input.Scope = authmodel.RateLimitScopeInternalRPC
		default:
			input.Scope = authmodel.RateLimitScopeAuth
		}
	}
}

func resolveSourceService(input *authcontrolif.RateLimitInput) string {
	if input == nil {
		return "gateway"
	}
	if trimmed := strings.TrimSpace(input.SourceService); trimmed != "" {
		return trimmed
	}
	return "gateway"
}

func mergeIdentityFromToken(
	identity *authmodel.IdentityContext,
	token *authmodel.TokenRecord,
) *authmodel.IdentityContext {
	if token == nil {
		return identity
	}
	if identity == nil {
		identity = &authmodel.IdentityContext{}
	}

	if identity.Principal.EntityType == "" || identity.Principal.EntityID == "" {
		identity.Principal = token.Principal
	}
	if identity.EntityType == "" {
		identity.EntityType = token.Principal.EntityType
	}
	if identity.EntityID == "" {
		identity.EntityID = token.Principal.EntityID
	}
	if identity.PrincipalID == "" {
		identity.PrincipalID = strings.TrimSpace(token.PrincipalID)
		if identity.PrincipalID == "" {
			identity.PrincipalID = strings.TrimSpace(identity.Principal.PrincipalID())
		}
	}
	if identity.SessionID == uuid.Nil {
		identity.SessionID = token.SessionID
	}
	if identity.TokenID == uuid.Nil {
		identity.TokenID = token.ID
	}
	if identity.TokenFamilyID == uuid.Nil {
		identity.TokenFamilyID = token.FamilyID
	}
	if identity.TokenType == "" {
		identity.TokenType = token.Type
	}
	if strings.TrimSpace(identity.Role) == "" {
		identity.Role = strings.TrimSpace(token.RoleSnapshot)
	}
	if len(identity.Scopes) == 0 {
		identity.Scopes = append([]string(nil), token.ScopeSnapshot...)
	}
	if strings.TrimSpace(identity.ClientID) == "" {
		identity.ClientID = strings.TrimSpace(token.ClientID)
	}
	if strings.TrimSpace(identity.GatewayID) == "" {
		identity.GatewayID = strings.TrimSpace(token.GatewayID)
	}
	if identity.IssuedAt.IsZero() {
		identity.IssuedAt = token.IssuedAt
	}
	if identity.ExpiresAt.IsZero() {
		identity.ExpiresAt = token.ExpiresAt
	}

	return identity
}

func identityFromSession(session *authmodel.Session) *authmodel.IdentityContext {
	if session == nil {
		return nil
	}

	principalID := strings.TrimSpace(session.PrincipalID)
	if principalID == "" {
		principalID = strings.TrimSpace(session.Principal.PrincipalID())
	}

	return &authmodel.IdentityContext{
		Principal:     session.Principal,
		EntityType:    session.EntityType,
		EntityID:      session.EntityID,
		PrincipalID:   principalID,
		SessionID:     session.ID,
		TokenFamilyID: session.TokenFamilyID,
		Scopes:        append([]string(nil), session.ScopeSnapshot...),
		Role:          strings.TrimSpace(session.RoleSnapshot),
		AuthMethod:    session.AuthMethod,
		SourceIP:      strings.TrimSpace(session.CreatedByIP),
		ClientID:      strings.TrimSpace(session.ClientID),
		GatewayID:     strings.TrimSpace(session.GatewayID),
		IssuedAt:      session.CreatedAt,
		ExpiresAt:     session.ExpiresAt,
	}
}

func cloneRateLimitInput(input *authcontrolif.RateLimitInput) *authcontrolif.RateLimitInput {
	if input == nil {
		return nil
	}

	cloned := *input
	cloned.Headers = copyStringMap(input.Headers)
	cloned.Tags = copyStringMap(input.Tags)
	if input.Identity != nil {
		cloned.Identity = cloneIdentity(input.Identity)
	}
	return &cloned
}

func cloneIdentity(identity *authmodel.IdentityContext) *authmodel.IdentityContext {
	if identity == nil {
		return nil
	}

	cloned := *identity
	cloned.Scopes = append([]string(nil), identity.Scopes...)
	return &cloned
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

func checkContext(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func disabledRateLimitDecision() *authmodel.RateLimitDecision {
	return &authmodel.RateLimitDecision{
		Allowed:    true,
		Remaining:  -1,
		SubjectKey: "disabled",
		Reason:     "auth control disabled",
	}
}
