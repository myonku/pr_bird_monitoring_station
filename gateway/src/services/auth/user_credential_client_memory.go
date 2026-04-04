package auth

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	authif "gateway/src/interfaces/auth"
	authmodel "gateway/src/models/auth"
	modelsystem "gateway/src/models/system"

	"github.com/google/uuid"
)

var _ authif.IUserCredentialAuthClient = (*MemoryUserCredentialAuthClient)(nil)

// MemoryUserCredentialAuthClient 提供网关侧用户认证转发的内存骨架实现。
type MemoryUserCredentialAuthClient struct {
	mu sync.RWMutex

	users    map[string]memoryUserCredential
	sessions map[uuid.UUID]*authmodel.Session

	tokenManager   authif.ITokenManager
	sessionService authif.ISessionService
}

type memoryUserCredential struct {
	UserID   string
	Username string
	Password string
	Role     string
	Scopes   []string
}

// NewMemoryUserCredentialAuthClient 创建网关侧用户认证客户端。
func NewMemoryUserCredentialAuthClient(
	tokenManager authif.ITokenManager,
	sessionService authif.ISessionService,
) *MemoryUserCredentialAuthClient {
	client := &MemoryUserCredentialAuthClient{
		users:          make(map[string]memoryUserCredential),
		sessions:       make(map[uuid.UUID]*authmodel.Session),
		tokenManager:   tokenManager,
		sessionService: sessionService,
	}

	// 开发阶段内置账号，便于联调 HTTP 登录流程。
	client.UpsertUserCredential("demo", "demo123", "user-demo", "user", []string{"client:basic"})
	client.UpsertUserCredential("admin", "admin123", "user-admin", "admin", []string{"client:basic", "client:admin"})

	return client
}

// UpsertUserCredential 注册或更新用户名密码条目。
func (c *MemoryUserCredentialAuthClient) UpsertUserCredential(
	username string,
	password string,
	userID string,
	role string,
	scopes []string,
) {
	if c == nil {
		return
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return
	}
	if userID == "" {
		userID = "user-" + username
	}
	if role == "" {
		role = "user"
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.users[username] = memoryUserCredential{
		UserID:   userID,
		Username: username,
		Password: password,
		Role:     role,
		Scopes:   append([]string(nil), scopes...),
	}
}

// AuthenticateByPassword 转发用户名/密码登录请求（内存模拟）。
func (c *MemoryUserCredentialAuthClient) AuthenticateByPassword(
	ctx context.Context,
	req *authmodel.UserPasswordAuthRequest,
) (*authmodel.UserPasswordAuthResult, error) {
	_ = ctx
	if c == nil || c.tokenManager == nil {
		return nil, &modelsystem.ErrUserAuthClientNotConfigured
	}
	if req == nil {
		return nil, &modelsystem.ErrUserPasswordAuthRequestNil
	}

	username := strings.TrimSpace(req.Username)
	if username == "" {
		return nil, &modelsystem.ErrUsernameRequired
	}
	if req.Password == "" {
		return nil, &modelsystem.ErrPasswordRequired
	}

	credential, ok := c.lookupCredential(username)
	if !ok || credential.Password != req.Password {
		return nil, &modelsystem.ErrInvalidUserCredentials
	}

	resolvedScopes := append([]string(nil), req.Scopes...)
	if len(resolvedScopes) == 0 {
		resolvedScopes = append([]string(nil), credential.Scopes...)
	}
	if len(resolvedScopes) == 0 {
		resolvedScopes = []string{"client:basic"}
	}

	now := time.Now()
	principal := authmodel.Principal{
		EntityType: authmodel.EntityUser,
		EntityID:   credential.UserID,
	}

	session := &authmodel.Session{
		ID:            uuid.New(),
		Principal:     principal,
		EntityType:    principal.EntityType,
		EntityID:      principal.EntityID,
		PrincipalID:   principal.PrincipalID(),
		Status:        authmodel.SessionActive,
		AuthMethod:    authmodel.AuthMethodPassword,
		CreatedByIP:   req.SourceIP,
		LastSeenIP:    req.SourceIP,
		UserAgent:     req.UserAgent,
		ClientID:      req.ClientID,
		GatewayID:     req.GatewayID,
		ScopeSnapshot: append([]string(nil), resolvedScopes...),
		RoleSnapshot:  credential.Role,
		TokenFamilyID: uuid.New(),
		CreatedAt:     now,
		UpdatedAt:     now,
		LastSeenAt:    now,
		NextRefreshAt: now.Add(30 * time.Minute),
		ExpiresAt:     now.Add(24 * time.Hour),
		Version:       1,
	}

	audience := strings.TrimSpace(req.Audience)
	if audience == "" {
		audience = "gateway"
	}

	access := &authmodel.IssuedToken{
		Raw:     fmt.Sprintf("%s.%s", authmodel.TokenAccess, uuid.NewString()),
		Type:    authmodel.TokenAccess,
		Storage: authmodel.TokenStorageCache,
		TTLSec:  300,
		Claims: authmodel.TokenClaims{
			Issuer:      "gateway",
			Audience:    audience,
			Subject:     credential.UserID,
			Type:        authmodel.TokenAccess,
			EntityType:  authmodel.EntityUser,
			EntityID:    credential.UserID,
			PrincipalID: principal.PrincipalID(),
			SessionID:   session.ID,
			TokenID:     uuid.New(),
			FamilyID:    session.TokenFamilyID,
			Role:        credential.Role,
			Scopes:      append([]string(nil), resolvedScopes...),
			AuthMethod:  authmodel.AuthMethodPassword,
			ClientID:    req.ClientID,
			GatewayID:   req.GatewayID,
			IssuedAt:    now,
			ExpiresAt:   now.Add(5 * time.Minute),
		},
	}
	refresh := &authmodel.IssuedToken{
		Raw:     fmt.Sprintf("%s.%s", authmodel.TokenRefresh, uuid.NewString()),
		Type:    authmodel.TokenRefresh,
		Storage: authmodel.TokenStorageDatabase,
		TTLSec:  86400,
		Claims: authmodel.TokenClaims{
			Issuer:      "gateway",
			Audience:    audience,
			Subject:     credential.UserID,
			Type:        authmodel.TokenRefresh,
			EntityType:  authmodel.EntityUser,
			EntityID:    credential.UserID,
			PrincipalID: principal.PrincipalID(),
			SessionID:   session.ID,
			TokenID:     uuid.New(),
			FamilyID:    session.TokenFamilyID,
			Role:        credential.Role,
			Scopes:      append([]string(nil), resolvedScopes...),
			AuthMethod:  authmodel.AuthMethodPassword,
			ClientID:    req.ClientID,
			GatewayID:   req.GatewayID,
			IssuedAt:    now,
			ExpiresAt:   now.Add(24 * time.Hour),
		},
	}

	bundle := authmodel.TokenBundle{AccessToken: access, RefreshToken: refresh}
	identity := &authmodel.IdentityContext{
		Principal:     principal,
		EntityType:    principal.EntityType,
		EntityID:      principal.EntityID,
		PrincipalID:   principal.PrincipalID(),
		SessionID:     session.ID,
		TokenID:       access.Claims.TokenID,
		TokenFamilyID: access.Claims.FamilyID,
		TokenType:     authmodel.TokenAccess,
		Role:          credential.Role,
		Scopes:        append([]string(nil), resolvedScopes...),
		AuthMethod:    authmodel.AuthMethodPassword,
		SourceIP:      req.SourceIP,
		ClientID:      req.ClientID,
		GatewayID:     req.GatewayID,
		UserAgent:     req.UserAgent,
		RequestID:     req.RequestID,
		TraceID:       req.TraceID,
		IssuedAt:      now,
		ExpiresAt:     access.Claims.ExpiresAt,
	}

	c.mu.Lock()
	c.sessions[session.ID] = cloneSessionForMemory(session)
	c.mu.Unlock()

	if setter, ok := c.tokenManager.(interface{ SetTokenBundleFromBootstrap(authmodel.TokenBundle) }); ok {
		setter.SetTokenBundleFromBootstrap(bundle)
	}
	if setter, ok := c.sessionService.(interface{ UpsertSessionFromBootstrap(*authmodel.Session) }); ok {
		setter.UpsertSessionFromBootstrap(session)
	}

	return &authmodel.UserPasswordAuthResult{
		Identity:  identity,
		Session:   session,
		Tokens:    bundle,
		IssuedAt:  now,
		ExpiresAt: access.Claims.ExpiresAt,
	}, nil
}

// RefreshByUserSession 转发 refresh token 续期请求。
func (c *MemoryUserCredentialAuthClient) RefreshByUserSession(
	ctx context.Context,
	req *authmodel.TokenRefreshRequest,
) (*authmodel.TokenBundle, error) {
	if c == nil || c.tokenManager == nil {
		return nil, &modelsystem.ErrUserAuthClientNotConfigured
	}
	if req == nil || req.RefreshToken == "" {
		return nil, &modelsystem.ErrRefreshTokenRequired
	}
	return c.tokenManager.Refresh(ctx, req)
}

// VerifyUserToken 转发用户 access token 校验请求。
func (c *MemoryUserCredentialAuthClient) VerifyUserToken(
	ctx context.Context,
	req *authmodel.TokenVerifyRequest,
) (*authmodel.TokenVerificationResult, error) {
	if c == nil || c.tokenManager == nil {
		return nil, &modelsystem.ErrUserAuthClientNotConfigured
	}
	if req == nil || req.RawToken == "" {
		return nil, &modelsystem.ErrRawTokenRequired
	}
	return c.tokenManager.Verify(ctx, req)
}

// RevokeUserToken 转发用户令牌撤销请求。
func (c *MemoryUserCredentialAuthClient) RevokeUserToken(
	ctx context.Context,
	req *authmodel.TokenRevokeRequest,
) error {
	if c == nil || c.tokenManager == nil {
		return &modelsystem.ErrUserAuthClientNotConfigured
	}
	if req == nil {
		return &modelsystem.ErrTokenRevokeRequestNil
	}
	return c.tokenManager.Revoke(ctx, req)
}

// RevokeUserSession 转发用户会话撤销请求。
func (c *MemoryUserCredentialAuthClient) RevokeUserSession(
	ctx context.Context,
	req *authmodel.SessionRevokeRequest,
) error {
	if c == nil {
		return &modelsystem.ErrUserAuthClientNotConfigured
	}
	if req == nil || req.SessionID == uuid.Nil {
		return &modelsystem.ErrSessionIDOrRefreshRequired
	}

	session := c.loadSession(req.SessionID)
	if session == nil && c.sessionService != nil {
		loaded, err := c.sessionService.GetSession(ctx, req.SessionID.String())
		if err == nil {
			session = loaded
		}
	}
	if session == nil {
		return &modelsystem.ErrSessionNotFound
	}

	if c.tokenManager != nil && session.TokenFamilyID != uuid.Nil {
		if err := c.tokenManager.Revoke(ctx, &authmodel.TokenRevokeRequest{
			FamilyID:  session.TokenFamilyID,
			SessionID: req.SessionID,
			Reason:    req.Reason,
			RevokedBy: req.RevokedBy,
			RequestID: req.RequestID,
			TraceID:   req.TraceID,
		}); err != nil {
			return err
		}
	}

	c.mu.Lock()
	if local, ok := c.sessions[req.SessionID]; ok {
		local.Status = authmodel.SessionRevoked
		local.RevokedAt = time.Now()
		local.UpdatedAt = time.Now()
		local.Version++
	}
	c.mu.Unlock()

	return nil
}

func (c *MemoryUserCredentialAuthClient) lookupCredential(username string) (memoryUserCredential, bool) {
	if c == nil {
		return memoryUserCredential{}, false
	}
	username = strings.ToLower(strings.TrimSpace(username))

	c.mu.RLock()
	defer c.mu.RUnlock()
	record, ok := c.users[username]
	if !ok {
		return memoryUserCredential{}, false
	}
	record.Scopes = append([]string(nil), record.Scopes...)
	return record, true
}

func (c *MemoryUserCredentialAuthClient) loadSession(sessionID uuid.UUID) *authmodel.Session {
	if c == nil || sessionID == uuid.Nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if session, ok := c.sessions[sessionID]; ok {
		return cloneSessionForMemory(session)
	}
	return nil
}

func cloneSessionForMemory(session *authmodel.Session) *authmodel.Session {
	if session == nil {
		return nil
	}
	copySession := *session
	copySession.ScopeSnapshot = append([]string(nil), session.ScopeSnapshot...)
	return &copySession
}
