package auth

import (
	"context"
	"strings"
	"sync"
	"time"

	authif "gateway/src/interfaces/auth"
	authmodel "gateway/src/models/auth"
	modelsystem "gateway/src/models/system"

	"github.com/google/uuid"
)

var _ authif.IModuleCredentialManager = (*ModuleCredentialManager)(nil)

const defaultModuleAccessRefreshLeewaySec int64 = 60

// ModuleCredentialManager 负责网关本模块凭证状态管理。
// 能力边界：持有本模块 session/token、按 refresh 续期、必要时回退 bootstrap。
type ModuleCredentialManager struct {
	Authority     authif.IAuthAuthorityClient
	BootstrapFlow authif.IBootstrapFlowCoordinator

	BootstrapReadyRequest *authmodel.BootstrapEnsureReadyRequest
	AccessRefreshLeeway   int64

	mu    sync.RWMutex
	state *authmodel.BootstrapAuthResult
}

func NewModuleCredentialManager(
	authority authif.IAuthAuthorityClient,
	bootstrapFlow authif.IBootstrapFlowCoordinator,
	bootstrapReq *authmodel.BootstrapEnsureReadyRequest,
) *ModuleCredentialManager {
	return &ModuleCredentialManager{
		Authority:             authority,
		BootstrapFlow:         bootstrapFlow,
		BootstrapReadyRequest: cloneBootstrapEnsureReadyRequest(bootstrapReq),
		AccessRefreshLeeway:   defaultModuleAccessRefreshLeewaySec,
	}
}

func (m *ModuleCredentialManager) EnsureActive(ctx context.Context) (*authmodel.BootstrapAuthResult, error) {
	if m == nil || m.Authority == nil || m.BootstrapFlow == nil {
		return nil, &modelsystem.ErrModuleCredentialDependenciesRequired
	}

	current := m.Snapshot()
	if current == nil || !hasRefreshToken(current.Tokens.RefreshToken) {
		return m.bootstrapAndPersist(ctx)
	}
	if !shouldRefreshAccess(current, m.AccessRefreshLeeway) {
		return current, nil
	}

	refreshed, err := m.Authority.RefreshModuleToken(ctx, &authmodel.TokenRefreshRequest{
		RefreshToken: strings.TrimSpace(current.Tokens.RefreshToken.Raw),
		ClientID:     pickClientID(current),
		GatewayID:    pickGatewayID(current),
		RequestID:    uuid.NewString(),
		TraceID:      uuid.NewString(),
	})
	if err != nil {
		return m.bootstrapAndPersist(ctx)
	}

	next, err := m.mergeRefreshedState(ctx, current, refreshed)
	if err != nil {
		return nil, err
	}

	m.setState(next)
	return m.Snapshot(), nil
}

func (m *ModuleCredentialManager) Snapshot() *authmodel.BootstrapAuthResult {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return cloneBootstrapAuthResult(m.state)
}

func (m *ModuleCredentialManager) Revoke(ctx context.Context, reason string, revokedBy string) error {
	if m == nil || m.Authority == nil {
		return &modelsystem.ErrModuleCredentialDependenciesRequired
	}
	current := m.Snapshot()
	if current == nil {
		return nil
	}

	var firstErr error
	sessionID := uuid.Nil
	if current.Identity != nil {
		sessionID = current.Identity.SessionID
	}
	if sessionID == uuid.Nil && current.Session != nil {
		sessionID = current.Session.ID
	}
	if sessionID != uuid.Nil {
		if err := m.Authority.RevokeModuleSession(ctx, &authmodel.SessionRevokeRequest{
			SessionID: sessionID,
			Reason:    strings.TrimSpace(reason),
			RevokedBy: strings.TrimSpace(revokedBy),
			RequestID: uuid.NewString(),
			TraceID:   uuid.NewString(),
		}); err != nil {
			firstErr = err
		}
	}

	familyID := uuid.Nil
	tokenID := uuid.Nil
	if current.Identity != nil {
		familyID = current.Identity.TokenFamilyID
		tokenID = current.Identity.TokenID
	}
	if familyID == uuid.Nil && current.Session != nil {
		familyID = current.Session.TokenFamilyID
	}
	if familyID != uuid.Nil || tokenID != uuid.Nil {
		if err := m.Authority.RevokeToken(ctx, &authmodel.TokenRevokeRequest{
			TokenID:   tokenID,
			FamilyID:  familyID,
			SessionID: sessionID,
			Reason:    strings.TrimSpace(reason),
			RevokedBy: strings.TrimSpace(revokedBy),
			RequestID: uuid.NewString(),
			TraceID:   uuid.NewString(),
		}); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	m.mu.Lock()
	m.state = nil
	m.mu.Unlock()
	return firstErr
}

func (m *ModuleCredentialManager) bootstrapAndPersist(
	ctx context.Context,
) (*authmodel.BootstrapAuthResult, error) {
	request := cloneBootstrapEnsureReadyRequest(m.BootstrapReadyRequest)
	if request == nil || request.ChallengeRequest == nil {
		return nil, &modelsystem.ErrModuleCredentialBootstrapRequestNeeded
	}

	result, err := m.BootstrapFlow.EnsureReady(ctx, request)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, &modelsystem.ErrAccessTokenNotAvailable
	}
	if !hasRefreshToken(result.Tokens.RefreshToken) {
		return nil, &modelsystem.ErrRefreshTokenRequired
	}
	if err = m.hydrateIdentityAndSession(ctx, result); err != nil {
		return nil, err
	}

	m.setState(result)
	return m.Snapshot(), nil
}

func (m *ModuleCredentialManager) mergeRefreshedState(
	ctx context.Context,
	base *authmodel.BootstrapAuthResult,
	bundle *authmodel.TokenBundle,
) (*authmodel.BootstrapAuthResult, error) {
	if bundle == nil {
		return nil, &modelsystem.ErrAccessTokenNotAvailable
	}

	next := cloneBootstrapAuthResult(base)
	if next == nil {
		next = &authmodel.BootstrapAuthResult{Stage: authmodel.BootstrapStageReady}
	}
	next.Stage = authmodel.BootstrapStageReady
	if bundle.AccessToken != nil {
		next.Tokens.AccessToken = cloneModuleIssuedToken(bundle.AccessToken)
	}
	if bundle.RefreshToken != nil {
		next.Tokens.RefreshToken = cloneModuleIssuedToken(bundle.RefreshToken)
	}
	if bundle.DownstreamToken != nil {
		next.Tokens.DownstreamToken = cloneModuleIssuedToken(bundle.DownstreamToken)
	}
	if !hasAccessToken(next.Tokens.AccessToken) {
		return nil, &modelsystem.ErrAccessTokenNotAvailable
	}
	if !hasRefreshToken(next.Tokens.RefreshToken) {
		return nil, &modelsystem.ErrRefreshTokenRequired
	}

	if err := m.hydrateIdentityAndSession(ctx, next); err != nil {
		return nil, err
	}
	if next.IssuedAt.IsZero() {
		next.IssuedAt = time.Now()
	}
	if next.ExpiresAt.IsZero() && next.Tokens.AccessToken != nil {
		next.ExpiresAt = next.Tokens.AccessToken.Claims.ExpiresAt
	}
	if next.ExpiresAt.IsZero() && next.Identity != nil {
		next.ExpiresAt = next.Identity.ExpiresAt
	}

	return next, nil
}

func (m *ModuleCredentialManager) hydrateIdentityAndSession(
	ctx context.Context,
	state *authmodel.BootstrapAuthResult,
) error {
	if state == nil || !hasAccessToken(state.Tokens.AccessToken) {
		return &modelsystem.ErrAccessTokenNotAvailable
	}

	accessRaw := strings.TrimSpace(state.Tokens.AccessToken.Raw)
	verifyRes, err := m.Authority.VerifyToken(ctx, &authmodel.TokenVerifyRequest{
		RawToken:      accessRaw,
		ExpectedTypes: []authmodel.TokenType{authmodel.TokenAccess, authmodel.TokenService},
	})
	if err != nil {
		return err
	}
	if verifyRes == nil || !verifyRes.Valid || verifyRes.Identity == nil {
		return &modelsystem.ErrAccessTokenNotAvailable
	}

	identity := cloneIdentityContext(verifyRes.Identity)
	if identity.GatewayID == "" {
		identity.GatewayID = pickGatewayID(state)
	}
	if identity.SourceService == "" {
		identity.SourceService = identity.EntityID
	}
	state.Identity = identity
	if !identity.ExpiresAt.IsZero() {
		state.ExpiresAt = identity.ExpiresAt
	}
	if state.Tokens.AccessToken != nil && !state.Tokens.AccessToken.Claims.IssuedAt.IsZero() {
		state.IssuedAt = state.Tokens.AccessToken.Claims.IssuedAt
	}

	if identity.SessionID == uuid.Nil {
		return nil
	}
	session, err := m.Authority.ValidateSession(ctx, &authmodel.SessionValidateRequest{
		SessionID:     identity.SessionID,
		PrincipalID:   identity.PrincipalID,
		RequireActive: true,
	})
	if err != nil {
		return err
	}
	if session != nil {
		state.Session = cloneSession(session)
	}
	return nil
}

func (m *ModuleCredentialManager) setState(state *authmodel.BootstrapAuthResult) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state = cloneBootstrapAuthResult(state)
}

func pickClientID(state *authmodel.BootstrapAuthResult) string {
	if state == nil || state.Identity == nil {
		return ""
	}
	return strings.TrimSpace(state.Identity.ClientID)
}

func pickGatewayID(state *authmodel.BootstrapAuthResult) string {
	if state == nil || state.Identity == nil {
		return ""
	}
	if v := strings.TrimSpace(state.Identity.GatewayID); v != "" {
		return v
	}
	return strings.TrimSpace(state.Identity.EntityID)
}

func shouldRefreshAccess(state *authmodel.BootstrapAuthResult, leewaySec int64) bool {
	if state == nil || !hasAccessToken(state.Tokens.AccessToken) {
		return true
	}
	if leewaySec <= 0 {
		leewaySec = defaultModuleAccessRefreshLeewaySec
	}

	expiresAt := state.Tokens.AccessToken.Claims.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = state.ExpiresAt
	}
	if expiresAt.IsZero() {
		return true
	}

	return time.Until(expiresAt) <= time.Duration(leewaySec)*time.Second
}

func hasAccessToken(token *authmodel.IssuedToken) bool {
	return token != nil && strings.TrimSpace(token.Raw) != ""
}

func hasRefreshToken(token *authmodel.IssuedToken) bool {
	return token != nil && strings.TrimSpace(token.Raw) != ""
}

func cloneBootstrapEnsureReadyRequest(req *authmodel.BootstrapEnsureReadyRequest) *authmodel.BootstrapEnsureReadyRequest {
	if req == nil {
		return nil
	}
	out := &authmodel.BootstrapEnsureReadyRequest{
		ChallengeRequest:       cloneChallengeRequest(req.ChallengeRequest),
		Role:                   req.Role,
		Scopes:                 append([]string(nil), req.Scopes...),
		RequireDownstreamToken: req.RequireDownstreamToken,
		Signer:                 req.Signer,
	}
	return out
}

func cloneChallengeRequest(req *authmodel.ChallengeRequest) *authmodel.ChallengeRequest {
	if req == nil {
		return nil
	}
	out := *req
	return &out
}

func cloneBootstrapAuthResult(in *authmodel.BootstrapAuthResult) *authmodel.BootstrapAuthResult {
	if in == nil {
		return nil
	}
	out := *in
	out.Identity = cloneIdentityContext(in.Identity)
	out.Session = cloneSession(in.Session)
	out.Tokens = cloneTokenBundle(in.Tokens)
	return &out
}

func cloneIdentityContext(in *authmodel.IdentityContext) *authmodel.IdentityContext {
	if in == nil {
		return nil
	}
	out := *in
	out.Scopes = append([]string(nil), in.Scopes...)
	return &out
}

func cloneSession(in *authmodel.Session) *authmodel.Session {
	if in == nil {
		return nil
	}
	out := *in
	out.ScopeSnapshot = append([]string(nil), in.ScopeSnapshot...)
	return &out
}

func cloneTokenBundle(in authmodel.TokenBundle) authmodel.TokenBundle {
	return authmodel.TokenBundle{
		AccessToken:     cloneModuleIssuedToken(in.AccessToken),
		RefreshToken:    cloneModuleIssuedToken(in.RefreshToken),
		DownstreamToken: cloneModuleIssuedToken(in.DownstreamToken),
	}
}

func cloneModuleIssuedToken(in *authmodel.IssuedToken) *authmodel.IssuedToken {
	if in == nil {
		return nil
	}
	out := *in
	out.Claims.Scopes = append([]string(nil), in.Claims.Scopes...)
	return &out
}
