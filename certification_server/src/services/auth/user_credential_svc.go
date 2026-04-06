package auth

import (
	"context"
	"strings"
	"sync"
	"time"

	interfaces "certification_server/src/interfaces/auth"
	authmodel "certification_server/src/models/auth"
	commonmodel "certification_server/src/models/common"
	modelsystem "certification_server/src/models/system"

	"github.com/google/uuid"
)

var _ interfaces.IUserCredentialAuthService = (*UserCredentialAuthService)(nil)

// UserCredentialAuthService 提供用户名/密码认证骨架实现。
type UserCredentialAuthService struct {
	mu sync.RWMutex

	users map[string]userCredentialRecord

	sessionSvc interfaces.ISessionService
	tokenSvc   interfaces.ITokenService
}

type userCredentialRecord struct {
	UserID   string
	Username string
	Password string
	Role     string
	Scopes   []string
}

// NewUserCredentialAuthService 创建用户凭据认证服务。
func NewUserCredentialAuthService(
	sessionSvc interfaces.ISessionService,
	tokenSvc interfaces.ITokenService,
) *UserCredentialAuthService {
	svc := &UserCredentialAuthService{
		users:      make(map[string]userCredentialRecord),
		sessionSvc: sessionSvc,
		tokenSvc:   tokenSvc,
	}

	// 开发阶段内置账号，用于联调用户名/密码认证链路。
	svc.UpsertUserCredential("demo", "demo123", "user-demo", "user", []string{"client:basic"})
	svc.UpsertUserCredential("admin", "admin123", "user-admin", "admin", []string{"client:basic", "client:admin"})

	return svc
}

// UpsertUserCredential 注册或更新用户名密码条目。
func (s *UserCredentialAuthService) UpsertUserCredential(
	username string,
	password string,
	userID string,
	role string,
	scopes []string,
) {
	if s == nil {
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

	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[username] = userCredentialRecord{
		UserID:   userID,
		Username: username,
		Password: password,
		Role:     role,
		Scopes:   append([]string(nil), scopes...),
	}
}

// AuthenticateByPassword 校验用户凭据并签发会话与令牌。
func (s *UserCredentialAuthService) AuthenticateByPassword(
	ctx context.Context,
	req *authmodel.UserPasswordAuthRequest,
) (*authmodel.UserPasswordAuthResult, error) {
	if s == nil || s.sessionSvc == nil || s.tokenSvc == nil {
		return nil, &modelsystem.ErrUserCredentialDepsNotReady
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

	credential, ok := s.lookupCredential(username)
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

	principal := authmodel.Principal{
		EntityType: commonmodel.EntityUser,
		EntityID:   credential.UserID,
	}

	now := time.Now()
	session, err := s.sessionSvc.CreateSession(ctx, &authmodel.SessionIssueRequest{
		Principal:  principal,
		Role:       credential.Role,
		Scopes:     append([]string(nil), resolvedScopes...),
		AuthMethod: authmodel.AuthMethodPassword,
		ClientID:   req.ClientID,
		GatewayID:  req.GatewayID,
		SourceIP:   req.SourceIP,
		UserAgent:  req.UserAgent,
		ExpiresAt:  now.Add(24 * time.Hour),
	})
	if err != nil {
		return nil, err
	}

	bundle, err := s.tokenSvc.IssueTokenBundle(ctx, session, &authmodel.TokenIssueRequest{
		Principal:  principal,
		Audience:   normalizeAudience(req.Audience),
		Role:       credential.Role,
		Scopes:     append([]string(nil), resolvedScopes...),
		AuthMethod: authmodel.AuthMethodPassword,
		ClientID:   req.ClientID,
		GatewayID:  req.GatewayID,
	})
	if err != nil {
		return nil, err
	}

	result := &authmodel.UserPasswordAuthResult{
		Session:  session,
		Tokens:   authmodel.TokenBundle{},
		IssuedAt: now,
	}
	if bundle != nil {
		result.Tokens = *bundle
	}

	identity := &authmodel.IdentityContext{
		Principal:   principal,
		EntityType:  principal.EntityType,
		EntityID:    principal.EntityID,
		PrincipalID: principal.PrincipalID(),
		SessionID:   session.ID,
		Role:        credential.Role,
		Scopes:      append([]string(nil), resolvedScopes...),
		AuthMethod:  authmodel.AuthMethodPassword,
		SourceIP:    req.SourceIP,
		ClientID:    req.ClientID,
		GatewayID:   req.GatewayID,
		UserAgent:   req.UserAgent,
		RequestID:   req.RequestID,
		TraceID:     req.TraceID,
		IssuedAt:    now,
		ExpiresAt:   session.ExpiresAt,
	}
	if result.Tokens.AccessToken != nil {
		identity.TokenID = result.Tokens.AccessToken.Claims.TokenID
		identity.TokenFamilyID = result.Tokens.AccessToken.Claims.FamilyID
		identity.TokenType = result.Tokens.AccessToken.Type
		identity.ExpiresAt = result.Tokens.AccessToken.Claims.ExpiresAt
		result.ExpiresAt = result.Tokens.AccessToken.Claims.ExpiresAt
	} else {
		result.ExpiresAt = session.ExpiresAt
	}

	result.Identity = identity
	return result, nil
}

// RefreshByUserSession 复用 token service 的 refresh 逻辑。
func (s *UserCredentialAuthService) RefreshByUserSession(
	ctx context.Context,
	req *authmodel.TokenRefreshRequest,
) (*authmodel.TokenBundle, error) {
	if s == nil || s.tokenSvc == nil {
		return nil, &modelsystem.ErrUserCredentialDepsNotReady
	}
	if req == nil || req.RefreshToken == "" {
		return nil, &modelsystem.ErrRefreshTokenRequired
	}
	return s.tokenSvc.RefreshTokenBundle(ctx, req)
}

// RevokeUserSession 撤销会话并联动撤销 refresh token family。
func (s *UserCredentialAuthService) RevokeUserSession(
	ctx context.Context,
	req *authmodel.SessionRevokeRequest,
) error {
	if s == nil || s.sessionSvc == nil || s.tokenSvc == nil {
		return &modelsystem.ErrUserCredentialDepsNotReady
	}
	if req == nil {
		return &modelsystem.ErrSessionRevokeRequestNil
	}

	var familyID uuid.UUID
	if req.SessionID != uuid.Nil {
		session, err := s.sessionSvc.GetSession(ctx, req.SessionID.String())
		if err == nil && session != nil {
			familyID = session.TokenFamilyID
		}
	}

	if err := s.sessionSvc.RevokeSession(ctx, req); err != nil {
		return err
	}

	if familyID != uuid.Nil {
		return s.tokenSvc.RevokeTokenFamily(ctx, familyID.String(), req.RevokedBy)
	}

	return nil
}

func (s *UserCredentialAuthService) lookupCredential(username string) (userCredentialRecord, bool) {
	if s == nil {
		return userCredentialRecord{}, false
	}
	username = strings.ToLower(strings.TrimSpace(username))

	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.users[username]
	if !ok {
		return userCredentialRecord{}, false
	}
	record.Scopes = append([]string(nil), record.Scopes...)
	return record, true
}

func normalizeAudience(audience string) string {
	audience = strings.TrimSpace(audience)
	if audience == "" {
		return "gateway"
	}
	return audience
}
