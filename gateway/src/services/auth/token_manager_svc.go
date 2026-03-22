package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	authif "gateway/src/interfaces/auth"
	authmodel "gateway/src/models/auth"
	modelsystem "gateway/src/models/system"
	"gateway/src/repo"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

var _ authif.ITokenManager = (*TokenManagerService)(nil)

// TokenManagerService 提供网关侧令牌状态缓存与续期行为。
type TokenManagerService struct {
	mu sync.RWMutex

	mysql *repo.MySQLClient
	redis *repo.RedisClient

	accessToken  *authmodel.IssuedToken
	refreshToken *authmodel.IssuedToken

	revokedByTokenID  map[uuid.UUID]struct{}
	revokedByFamilyID map[uuid.UUID]struct{}
}

func NewTokenManagerService() *TokenManagerService {
	return NewTokenManagerServiceWithInfra(nil, nil)
}

func NewTokenManagerServiceWithInfra(mysql *repo.MySQLClient, redis *repo.RedisClient) *TokenManagerService {
	return &TokenManagerService{
		mysql:             mysql,
		redis:             redis,
		revokedByTokenID:  make(map[uuid.UUID]struct{}),
		revokedByFamilyID: make(map[uuid.UUID]struct{}),
	}
}

// SetTokenBundleFromBootstrap 写入 bootstrap 返回的令牌。
func (s *TokenManagerService) SetTokenBundleFromBootstrap(bundle authmodel.TokenBundle) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if bundle.AccessToken != nil {
		clone := *bundle.AccessToken
		s.accessToken = &clone
		_ = s.cacheToken(context.Background(), &clone)
	}
	if bundle.RefreshToken != nil {
		clone := *bundle.RefreshToken
		s.refreshToken = &clone
		_ = s.cacheToken(context.Background(), &clone)
		_ = s.persistRefreshToken(context.Background(), &clone)
	}
}

func (s *TokenManagerService) GetAccessToken(ctx context.Context) (*authmodel.IssuedToken, error) {
	_ = ctx
	if s == nil {
		return nil, &modelsystem.ErrTokenManagerNotConfigured
	}

	s.mu.RLock()
	token := s.accessToken
	refresh := s.refreshToken
	s.mu.RUnlock()
	if token != nil && time.Now().Before(token.Claims.ExpiresAt) {
		clone := *token
		return &clone, nil
	}

	if token == nil {
		cachedAccess, _ := s.loadTokenFromCache(ctx, authmodel.TokenAccess)
		if cachedAccess != nil {
			s.mu.Lock()
			s.accessToken = cachedAccess
			token = cachedAccess
			s.mu.Unlock()
		}
	}
	if token != nil && time.Now().Before(token.Claims.ExpiresAt) {
		clone := *token
		return &clone, nil
	}

	if refresh == nil {
		cachedRefresh, _ := s.loadTokenFromCache(ctx, authmodel.TokenRefresh)
		if cachedRefresh == nil {
			cachedRefresh, _ = s.loadLatestRefreshFromDB(ctx)
		}
		if cachedRefresh != nil {
			s.mu.Lock()
			s.refreshToken = cachedRefresh
			refresh = cachedRefresh
			s.mu.Unlock()
		}
	}

	if refresh == nil {
		return nil, &modelsystem.ErrAccessTokenNotAvailable
	}

	bundle, err := s.Refresh(context.Background(), &authmodel.TokenRefreshRequest{RefreshToken: refresh.Raw})
	if err != nil {
		return nil, err
	}
	if bundle == nil || bundle.AccessToken == nil {
		return nil, &modelsystem.ErrAccessTokenNotAvailable
	}
	clone := *bundle.AccessToken
	return &clone, nil
}

func (s *TokenManagerService) Refresh(ctx context.Context, req *authmodel.TokenRefreshRequest) (*authmodel.TokenBundle, error) {
	if s == nil {
		return nil, &modelsystem.ErrTokenManagerNotConfigured
	}
	if req == nil || req.RefreshToken == "" {
		return nil, &modelsystem.ErrRefreshTokenRequired
	}

	refreshToken, err := s.resolveRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if refreshToken == nil {
		return nil, &modelsystem.ErrRefreshTokenNotFound
	}
	if time.Now().After(refreshToken.Claims.ExpiresAt) {
		return nil, &modelsystem.ErrRefreshTokenExpired
	}

	familyID := refreshToken.Claims.FamilyID
	if _, revoked := s.revokedByFamilyID[familyID]; revoked {
		return nil, &modelsystem.ErrTokenFamilyRevoked
	}
	if _, revoked := s.revokedByTokenID[refreshToken.Claims.TokenID]; revoked {
		return nil, &modelsystem.ErrRefreshTokenRevoked
	}

	now := time.Now()
	accessToken := &authmodel.IssuedToken{
		Raw:     fmt.Sprintf("%s.%s", authmodel.TokenAccess, uuid.NewString()),
		Type:    authmodel.TokenAccess,
		Storage: authmodel.TokenStorageCache,
		TTLSec:  300,
		Claims: authmodel.TokenClaims{
			Issuer:        "gateway",
			Audience:      refreshToken.Claims.Audience,
			Subject:       refreshToken.Claims.Subject,
			Type:          authmodel.TokenAccess,
			EntityType:    refreshToken.Claims.EntityType,
			EntityID:      refreshToken.Claims.EntityID,
			PrincipalID:   refreshToken.Claims.PrincipalID,
			SessionID:     refreshToken.Claims.SessionID,
			TokenID:       uuid.New(),
			FamilyID:      familyID,
			ParentID:      refreshToken.Claims.TokenID,
			Role:          refreshToken.Claims.Role,
			Scopes:        append([]string(nil), refreshToken.Claims.Scopes...),
			AuthMethod:    authmodel.AuthMethodRefreshToken,
			ClientID:      req.ClientID,
			GatewayID:     req.GatewayID,
			SourceService: refreshToken.Claims.SourceService,
			TargetService: refreshToken.Claims.TargetService,
			IssuedAt:      now,
			ExpiresAt:     now.Add(300 * time.Second),
		},
	}

	newRefresh := &authmodel.IssuedToken{
		Raw:     fmt.Sprintf("%s.%s", authmodel.TokenRefresh, uuid.NewString()),
		Type:    authmodel.TokenRefresh,
		Storage: authmodel.TokenStorageDatabase,
		TTLSec:  86400,
		Claims: authmodel.TokenClaims{
			Issuer:        "gateway",
			Audience:      refreshToken.Claims.Audience,
			Subject:       refreshToken.Claims.Subject,
			Type:          authmodel.TokenRefresh,
			EntityType:    refreshToken.Claims.EntityType,
			EntityID:      refreshToken.Claims.EntityID,
			PrincipalID:   refreshToken.Claims.PrincipalID,
			SessionID:     refreshToken.Claims.SessionID,
			TokenID:       uuid.New(),
			FamilyID:      familyID,
			ParentID:      refreshToken.Claims.TokenID,
			Role:          refreshToken.Claims.Role,
			Scopes:        append([]string(nil), refreshToken.Claims.Scopes...),
			AuthMethod:    authmodel.AuthMethodRefreshToken,
			ClientID:      req.ClientID,
			GatewayID:     req.GatewayID,
			SourceService: refreshToken.Claims.SourceService,
			TargetService: refreshToken.Claims.TargetService,
			IssuedAt:      now,
			ExpiresAt:     now.Add(24 * time.Hour),
		},
	}

	s.revokedByTokenID[refreshToken.Claims.TokenID] = struct{}{}
	s.accessToken = accessToken
	s.refreshToken = newRefresh
	_ = s.cacheToken(ctx, accessToken)
	_ = s.cacheToken(ctx, newRefresh)
	_ = s.cacheRevocation(ctx, refreshToken.Claims.TokenID, familyID)
	_ = s.persistRefreshToken(ctx, newRefresh)

	return &authmodel.TokenBundle{AccessToken: accessToken, RefreshToken: newRefresh}, nil
}

func (s *TokenManagerService) Verify(ctx context.Context, req *authmodel.TokenVerifyRequest) (*authmodel.TokenVerificationResult, error) {
	_ = ctx
	if s == nil {
		return nil, &modelsystem.ErrTokenManagerNotConfigured
	}
	if req == nil || req.RawToken == "" {
		return nil, &modelsystem.ErrRawTokenRequired
	}

	s.mu.RLock()
	candidates := []*authmodel.IssuedToken{s.accessToken, s.refreshToken}
	s.mu.RUnlock()

	var token *authmodel.IssuedToken
	for _, item := range candidates {
		if item != nil && item.Raw == req.RawToken {
			token = item
			break
		}
	}
	if token == nil {
		cachedByType, _ := s.loadTokenFromCache(ctx, inferTokenTypeByRaw(req.RawToken))
		if cachedByType != nil && cachedByType.Raw == req.RawToken {
			token = cachedByType
		}
	}
	if token == nil && shouldTryTokenDBByRaw(req.RawToken) {
		dbToken, _ := s.loadRefreshByRawFromDB(ctx, req.RawToken)
		if dbToken != nil {
			token = dbToken
			s.mu.Lock()
			s.refreshToken = dbToken
			s.mu.Unlock()
			_ = s.cacheToken(ctx, dbToken)
		}
	}
	if token == nil {
		return &authmodel.TokenVerificationResult{Valid: false, FailureReason: "token not found"}, nil
	}

	s.mu.RLock()
	_, revokedToken := s.revokedByTokenID[token.Claims.TokenID]
	_, revokedFamily := s.revokedByFamilyID[token.Claims.FamilyID]
	s.mu.RUnlock()
	if !revokedToken && !revokedFamily {
		tokenRevoked, familyRevoked, _ := s.loadRevocation(ctx, token.Claims.TokenID, token.Claims.FamilyID)
		revokedToken = tokenRevoked
		revokedFamily = familyRevoked
	}
	if revokedToken || revokedFamily {
		return &authmodel.TokenVerificationResult{Valid: false, Status: authmodel.TokenStatusRevoked, FailureReason: "token revoked"}, nil
	}

	if time.Now().After(token.Claims.ExpiresAt.Add(time.Duration(req.AllowExpiredSkewSec) * time.Second)) {
		return &authmodel.TokenVerificationResult{Valid: false, Status: authmodel.TokenStatusExpired, FailureReason: "token expired"}, nil
	}

	if len(req.ExpectedTypes) > 0 {
		matched := false
		for _, typ := range req.ExpectedTypes {
			if typ == token.Type {
				matched = true
				break
			}
		}
		if !matched {
			return &authmodel.TokenVerificationResult{Valid: false, FailureReason: "unexpected token type"}, nil
		}
	}

	identity := &authmodel.IdentityContext{
		Principal:     authmodel.Principal{EntityType: token.Claims.EntityType, EntityID: token.Claims.EntityID},
		EntityType:    token.Claims.EntityType,
		EntityID:      token.Claims.EntityID,
		PrincipalID:   token.Claims.PrincipalID,
		SessionID:     token.Claims.SessionID,
		TokenID:       token.Claims.TokenID,
		TokenFamilyID: token.Claims.FamilyID,
		TokenType:     token.Type,
		Role:          token.Claims.Role,
		Scopes:        append([]string(nil), token.Claims.Scopes...),
		AuthMethod:    token.Claims.AuthMethod,
		ClientID:      token.Claims.ClientID,
		GatewayID:     token.Claims.GatewayID,
		SourceService: token.Claims.SourceService,
		TargetService: token.Claims.TargetService,
		IssuedAt:      token.Claims.IssuedAt,
		ExpiresAt:     token.Claims.ExpiresAt,
	}

	record := &authmodel.TokenRecord{
		ID:            token.Claims.TokenID,
		FamilyID:      token.Claims.FamilyID,
		SessionID:     token.Claims.SessionID,
		Type:          token.Type,
		Status:        authmodel.TokenStatusActive,
		Storage:       token.Storage,
		Principal:     identity.Principal,
		PrincipalID:   identity.PrincipalID,
		ClientID:      token.Claims.ClientID,
		GatewayID:     token.Claims.GatewayID,
		RoleSnapshot:  token.Claims.Role,
		ScopeSnapshot: append([]string(nil), token.Claims.Scopes...),
		IssuedAt:      token.Claims.IssuedAt,
		ExpiresAt:     token.Claims.ExpiresAt,
	}

	return &authmodel.TokenVerificationResult{Valid: true, Status: authmodel.TokenStatusActive, Identity: identity, Token: record}, nil
}

func (s *TokenManagerService) Revoke(ctx context.Context, req *authmodel.TokenRevokeRequest) error {
	_ = ctx
	if s == nil {
		return &modelsystem.ErrTokenManagerNotConfigured
	}
	if req == nil {
		return &modelsystem.ErrTokenRevokeRequestNil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if req.FamilyID != uuid.Nil {
		s.revokedByFamilyID[req.FamilyID] = struct{}{}
	}
	if req.TokenID != uuid.Nil {
		s.revokedByTokenID[req.TokenID] = struct{}{}
	}
	if req.TokenID == uuid.Nil && req.FamilyID == uuid.Nil {
		return &modelsystem.ErrTokenIDOrFamilyIDRequired
	}
	_ = s.cacheRevocation(ctx, req.TokenID, req.FamilyID)
	return nil
}

func (s *TokenManagerService) resolveRefreshToken(ctx context.Context, raw string) (*authmodel.IssuedToken, error) {
	s.mu.RLock()
	local := s.refreshToken
	s.mu.RUnlock()
	if local != nil && local.Raw == raw {
		clone := *local
		return &clone, nil
	}

	cached, cacheErr := s.loadTokenFromCache(ctx, authmodel.TokenRefresh)
	if cacheErr == nil && cached != nil && cached.Raw == raw {
		return cached, nil
	}

	dbToken, dbErr := s.loadRefreshByRawFromDB(ctx, raw)
	if dbErr == nil && dbToken != nil {
		return dbToken, nil
	}

	return nil, &modelsystem.ErrRefreshTokenNotFound
}

func (s *TokenManagerService) cacheToken(ctx context.Context, token *authmodel.IssuedToken) error {
	if s.redis == nil || token == nil {
		return nil
	}
	body, err := json.Marshal(token)
	if err != nil {
		return err
	}
	ttl := time.Until(token.Claims.ExpiresAt)
	if ttl <= 0 {
		ttl = time.Duration(token.TTLSec) * time.Second
	}
	if ttl <= 0 {
		ttl = 10 * time.Second
	}
	return s.redis.Set(ctx, "auth:token:"+string(token.Type)+":latest", body, ttl)
}

func (s *TokenManagerService) loadTokenFromCache(ctx context.Context, tokenType authmodel.TokenType) (*authmodel.IssuedToken, error) {
	if s.redis == nil {
		return nil, &modelsystem.ErrNilRedisClient
	}
	raw, err := s.redis.Get(ctx, "auth:token:"+string(tokenType)+":latest")
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}
	if raw == "" {
		return nil, nil
	}
	var token authmodel.IssuedToken
	if err := json.Unmarshal([]byte(raw), &token); err != nil {
		return nil, err
	}
	return &token, nil
}

func (s *TokenManagerService) persistRefreshToken(ctx context.Context, token *authmodel.IssuedToken) error {
	if s.mysql == nil || token == nil || token.Type != authmodel.TokenRefresh {
		return nil
	}
	claimsJSON, err := json.Marshal(token.Claims)
	if err != nil {
		return err
	}
	_, err = s.mysql.Exec(ctx, `
INSERT INTO auth_token (
  token_id, family_id, session_id, principal_id, token_type, token_status,
  token_storage, raw_token, claims_json, issued_at, expires_at, revoked_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
  token_status=VALUES(token_status),
  token_storage=VALUES(token_storage),
  claims_json=VALUES(claims_json),
  issued_at=VALUES(issued_at),
  expires_at=VALUES(expires_at),
  revoked_at=VALUES(revoked_at)
`,
		token.Claims.TokenID.String(),
		token.Claims.FamilyID.String(),
		token.Claims.SessionID.String(),
		token.Claims.PrincipalID,
		string(token.Type),
		string(authmodel.TokenStatusActive),
		string(token.Storage),
		token.Raw,
		string(claimsJSON),
		token.Claims.IssuedAt,
		token.Claims.ExpiresAt,
		nil,
	)
	return err
}

func (s *TokenManagerService) loadLatestRefreshFromDB(ctx context.Context) (*authmodel.IssuedToken, error) {
	if s.mysql == nil {
		return nil, &modelsystem.ErrNilMySQLClient
	}
	type row struct {
		RawToken   string    `db:"raw_token"`
		ClaimsJSON string    `db:"claims_json"`
		ExpiresAt  time.Time `db:"expires_at"`
	}
	var r row
	err := s.mysql.Get(ctx, &r, `
SELECT raw_token, claims_json, expires_at
FROM auth_token
WHERE token_type = ? AND token_status = ?
ORDER BY issued_at DESC
LIMIT 1
`, string(authmodel.TokenRefresh), string(authmodel.TokenStatusActive))
	if err != nil {
		if repo.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return parseRefreshRow(r.RawToken, r.ClaimsJSON, r.ExpiresAt)
}

func (s *TokenManagerService) loadRefreshByRawFromDB(ctx context.Context, rawToken string) (*authmodel.IssuedToken, error) {
	if s.mysql == nil {
		return nil, &modelsystem.ErrNilMySQLClient
	}
	type row struct {
		RawToken   string    `db:"raw_token"`
		ClaimsJSON string    `db:"claims_json"`
		ExpiresAt  time.Time `db:"expires_at"`
	}
	var r row
	err := s.mysql.Get(ctx, &r, `
SELECT raw_token, claims_json, expires_at
FROM auth_token
WHERE raw_token = ? AND token_type = ?
LIMIT 1
`, rawToken, string(authmodel.TokenRefresh))
	if err != nil {
		if repo.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return parseRefreshRow(r.RawToken, r.ClaimsJSON, r.ExpiresAt)
}

func parseRefreshRow(rawToken, claimsJSON string, expiresAt time.Time) (*authmodel.IssuedToken, error) {
	if rawToken == "" {
		return nil, nil
	}
	claims := authmodel.TokenClaims{}
	if claimsJSON != "" {
		if err := json.Unmarshal([]byte(claimsJSON), &claims); err != nil {
			return nil, err
		}
	}
	if claims.TokenID == uuid.Nil {
		claims.TokenID = parseTokenUUID(rawToken)
	}
	if claims.ExpiresAt.IsZero() {
		claims.ExpiresAt = expiresAt
	}
	if claims.Type == "" {
		claims.Type = authmodel.TokenRefresh
	}
	return &authmodel.IssuedToken{
		Raw:     rawToken,
		Type:    authmodel.TokenRefresh,
		Storage: authmodel.TokenStorageDatabase,
		Claims:  claims,
		TTLSec:  int64(time.Until(claims.ExpiresAt) / time.Second),
	}, nil
}

func parseTokenUUID(rawToken string) uuid.UUID {
	parts := strings.Split(rawToken, ".")
	if len(parts) < 2 {
		return uuid.Nil
	}
	id, err := uuid.Parse(parts[1])
	if err != nil {
		return uuid.Nil
	}
	return id
}

func shouldTryTokenDBByRaw(rawToken string) bool {
	if rawToken == "" {
		return false
	}
	return strings.HasPrefix(rawToken, string(authmodel.TokenRefresh)+".")
}

func inferTokenTypeByRaw(rawToken string) authmodel.TokenType {
	if strings.HasPrefix(rawToken, string(authmodel.TokenRefresh)+".") {
		return authmodel.TokenRefresh
	}
	return authmodel.TokenAccess
}

func (s *TokenManagerService) cacheRevocation(ctx context.Context, tokenID, familyID uuid.UUID) error {
	if s.redis == nil {
		return nil
	}
	if tokenID != uuid.Nil {
		_ = s.redis.Set(ctx, "auth:token:revoked:id:"+tokenID.String(), "1", 24*time.Hour)
	}
	if familyID != uuid.Nil {
		_ = s.redis.Set(ctx, "auth:token:revoked:family:"+familyID.String(), "1", 24*time.Hour)
	}
	return nil
}

func (s *TokenManagerService) loadRevocation(ctx context.Context, tokenID, familyID uuid.UUID) (bool, bool, error) {
	if s.redis == nil {
		return false, false, &modelsystem.ErrNilRedisClient
	}
	revokedToken := false
	revokedFamily := false
	if tokenID != uuid.Nil {
		if v, err := s.redis.Get(ctx, "auth:token:revoked:id:"+tokenID.String()); err == nil && v != "" {
			revokedToken = true
		} else if err != nil && err != redis.Nil {
			return false, false, err
		}
	}
	if familyID != uuid.Nil {
		if v, err := s.redis.Get(ctx, "auth:token:revoked:family:"+familyID.String()); err == nil && v != "" {
			revokedFamily = true
		} else if err != nil && err != redis.Nil {
			return false, false, err
		}
	}
	return revokedToken, revokedFamily, nil
}
