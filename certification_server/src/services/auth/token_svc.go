package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	interfaces "certification_server/src/interfaces/auth"
	authmodel "certification_server/src/models/auth"
	"certification_server/src/repo"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

var _ interfaces.ITokenService = (*TokenService)(nil)

const (
	defaultAccessTTLSeconds  int64 = 300
	defaultRefreshTTLSeconds int64 = 86400
	defaultServiceTTLSeconds int64 = 600
	defaultGrantTTLSeconds   int64 = 120
)

// TokenService 提供认证中心令牌签发、校验与撤销的内存实现。
type TokenService struct {
	mu sync.RWMutex

	mysql *repo.MySQLClient
	redis *repo.RedisClient

	byRaw    map[string]*authmodel.TokenRecord
	byToken  map[uuid.UUID]*authmodel.TokenRecord
	byFamily map[uuid.UUID]map[uuid.UUID]*authmodel.TokenRecord
}

func NewTokenService(mysql *repo.MySQLClient, redis *repo.RedisClient) *TokenService {
	return &TokenService{
		mysql:    mysql,
		redis:    redis,
		byRaw:    make(map[string]*authmodel.TokenRecord),
		byToken:  make(map[uuid.UUID]*authmodel.TokenRecord),
		byFamily: make(map[uuid.UUID]map[uuid.UUID]*authmodel.TokenRecord),
	}
}

// IssueToken 根据认证上下文和请求参数签发新的令牌。
func (s *TokenService) IssueToken(
	ctx context.Context, req *authmodel.TokenIssueRequest) (*authmodel.IssuedToken, error) {

	if req == nil {
		return nil, fmt.Errorf("token issue request is nil")
	}
	if req.Principal.PrincipalID() == "" {
		return nil, fmt.Errorf("principal is required")
	}

	now := time.Now()
	ttlSec := req.TTLSec
	if ttlSec <= 0 {
		ttlSec = defaultTTLByType(req.TokenType)
	}

	tokenID := uuid.New()
	familyID := req.FamilyID
	if familyID == uuid.Nil {
		familyID = uuid.New()
	}

	raw := buildRawToken(req.TokenType, tokenID)
	claims := authmodel.TokenClaims{
		Issuer:        "certification_server",
		Audience:      req.Audience,
		Subject:       req.Principal.EntityID,
		Type:          req.TokenType,
		EntityType:    req.Principal.EntityType,
		EntityID:      req.Principal.EntityID,
		PrincipalID:   req.Principal.PrincipalID(),
		SessionID:     req.SessionID,
		TokenID:       tokenID,
		FamilyID:      familyID,
		ParentID:      req.ParentTokenID,
		Role:          req.Role,
		Scopes:        append([]string(nil), req.Scopes...),
		AuthMethod:    req.AuthMethod,
		ClientID:      req.ClientID,
		GatewayID:     req.GatewayID,
		SourceService: req.SourceService,
		TargetService: req.TargetService,
		IssuedAt:      now,
		ExpiresAt:     now.Add(time.Duration(ttlSec) * time.Second),
	}

	record := &authmodel.TokenRecord{
		ID:            tokenID,
		FamilyID:      familyID,
		SessionID:     req.SessionID,
		Type:          req.TokenType,
		Status:        authmodel.TokenStatusActive,
		Storage:       storageByType(req.TokenType),
		Principal:     req.Principal,
		PrincipalID:   req.Principal.PrincipalID(),
		ParentTokenID: req.ParentTokenID,
		ClientID:      req.ClientID,
		GatewayID:     req.GatewayID,
		RoleSnapshot:  req.Role,
		ScopeSnapshot: append([]string(nil), req.Scopes...),
		IssuedAt:      claims.IssuedAt,
		ExpiresAt:     claims.ExpiresAt,
	}

	s.mu.Lock()
	s.byRaw[raw] = record
	s.byToken[tokenID] = record
	if s.byFamily[familyID] == nil {
		s.byFamily[familyID] = make(map[uuid.UUID]*authmodel.TokenRecord)
	}
	s.byFamily[familyID][tokenID] = record
	s.mu.Unlock()

	_ = s.persistTokenRecord(ctx, raw, record, &claims)
	_ = s.cacheToken(ctx, raw, record, &claims)

	return &authmodel.IssuedToken{
		Raw:     raw,
		Type:    req.TokenType,
		Storage: record.Storage,
		Claims:  claims,
		TTLSec:  ttlSec,
	}, nil
}

// IssueTokenBundle 根据认证上下文和请求参数签发访问令牌和刷新令牌的组合。
func (s *TokenService) IssueTokenBundle(
	ctx context.Context, session *authmodel.Session, req *authmodel.TokenIssueRequest,
) (*authmodel.TokenBundle, error) {

	if session == nil {
		return nil, fmt.Errorf("session is nil")
	}
	if req == nil {
		return nil, fmt.Errorf("token issue request is nil")
	}

	common := *req
	common.SessionID = session.ID
	common.FamilyID = session.TokenFamilyID
	if common.FamilyID == uuid.Nil {
		common.FamilyID = uuid.New()
	}
	if common.Principal.PrincipalID() == "" {
		common.Principal = session.Principal
	}
	if common.Role == "" {
		common.Role = session.RoleSnapshot
	}
	if len(common.Scopes) == 0 {
		common.Scopes = append([]string(nil), session.ScopeSnapshot...)
	}

	accessReq := common
	accessReq.TokenType = authmodel.TokenAccess
	accessToken, err := s.IssueToken(ctx, &accessReq)
	if err != nil {
		return nil, err
	}

	refreshReq := common
	refreshReq.TokenType = authmodel.TokenRefresh
	refreshToken, err := s.IssueToken(ctx, &refreshReq)
	if err != nil {
		return nil, err
	}

	return &authmodel.TokenBundle{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// RefreshTokenBundle 根据刷新令牌刷新访问令牌和刷新令牌的组合。
func (s *TokenService) RefreshTokenBundle(
	ctx context.Context, req *authmodel.TokenRefreshRequest) (*authmodel.TokenBundle, error) {

	if req == nil || req.RefreshToken == "" {
		return nil, fmt.Errorf("refresh token is required")
	}

	s.mu.RLock()
	record, ok := s.byRaw[req.RefreshToken]
	s.mu.RUnlock()
	if (!ok || record == nil) && s.redis != nil {
		cachedRecord, _, cacheErr := s.loadTokenFromCache(ctx, req.RefreshToken)
		if cacheErr == nil && cachedRecord != nil {
			record = cachedRecord
			ok = true
		}
	}
	if (!ok || record == nil) && s.mysql != nil {
		dbRecord, _, dbErr := s.loadTokenFromDB(ctx, req.RefreshToken)
		if dbErr == nil && dbRecord != nil {
			record = dbRecord
			ok = true
			s.mu.Lock()
			s.byRaw[req.RefreshToken] = dbRecord
			s.byToken[dbRecord.ID] = dbRecord
			if s.byFamily[dbRecord.FamilyID] == nil {
				s.byFamily[dbRecord.FamilyID] = make(map[uuid.UUID]*authmodel.TokenRecord)
			}
			s.byFamily[dbRecord.FamilyID][dbRecord.ID] = dbRecord
			s.mu.Unlock()
		}
	}
	if !ok || record == nil {
		return nil, fmt.Errorf("refresh token not found")
	}
	if record.Type != authmodel.TokenRefresh {
		return nil, fmt.Errorf("token is not refresh type")
	}
	if record.Status != authmodel.TokenStatusActive || time.Now().After(record.ExpiresAt) {
		return nil, fmt.Errorf("refresh token is not active")
	}

	issueReq := &authmodel.TokenIssueRequest{
		Principal:     record.Principal,
		TokenType:     authmodel.TokenAccess,
		SessionID:     record.SessionID,
		FamilyID:      record.FamilyID,
		Audience:      "internal",
		Role:          record.RoleSnapshot,
		Scopes:        append([]string(nil), record.ScopeSnapshot...),
		AuthMethod:    authmodel.AuthMethodRefreshToken,
		ClientID:      req.ClientID,
		GatewayID:     req.GatewayID,
		ParentTokenID: record.ID,
	}
	access, err := s.IssueToken(ctx, issueReq)
	if err != nil {
		return nil, err
	}

	refreshReq := *issueReq
	refreshReq.TokenType = authmodel.TokenRefresh
	refreshReq.ParentTokenID = record.ID
	newRefresh, err := s.IssueToken(ctx, &refreshReq)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	record.Status = authmodel.TokenStatusRotated
	record.RevokedAt = time.Now()
	s.mu.Unlock()

	_ = s.updateTokenStatus(ctx, record.ID, authmodel.TokenStatusRotated)
	_ = s.cacheToken(ctx, req.RefreshToken, record, nil)

	return &authmodel.TokenBundle{AccessToken: access, RefreshToken: newRefresh}, nil
}

// VerifyToken 根据原始令牌字符串验证令牌的有效性和提取认证上下文。
func (s *TokenService) VerifyToken(
	ctx context.Context, req *authmodel.TokenVerifyRequest) (*authmodel.TokenVerificationResult, error) {

	if req == nil || req.RawToken == "" {
		return nil, fmt.Errorf("raw token is required")
	}

	s.mu.RLock()
	record, ok := s.byRaw[req.RawToken]
	s.mu.RUnlock()
	var claims *authmodel.TokenClaims
	if (!ok || record == nil) && s.redis != nil {
		cachedRecord, cachedClaims, cacheErr := s.loadTokenFromCache(ctx, req.RawToken)
		if cacheErr == nil && cachedRecord != nil {
			record = cachedRecord
			claims = cachedClaims
			ok = true
		}
	}
	if (!ok || record == nil) && s.mysql != nil {
		dbRecord, dbClaims, dbErr := s.loadTokenFromDB(ctx, req.RawToken)
		if dbErr == nil && dbRecord != nil {
			record = dbRecord
			claims = dbClaims
			ok = true
			s.mu.Lock()
			s.byRaw[req.RawToken] = dbRecord
			s.byToken[dbRecord.ID] = dbRecord
			if s.byFamily[dbRecord.FamilyID] == nil {
				s.byFamily[dbRecord.FamilyID] = make(map[uuid.UUID]*authmodel.TokenRecord)
			}
			s.byFamily[dbRecord.FamilyID][dbRecord.ID] = dbRecord
			s.mu.Unlock()
			_ = s.cacheToken(ctx, req.RawToken, dbRecord, dbClaims)
		}
	}
	if !ok || record == nil {
		return &authmodel.TokenVerificationResult{Valid: false, FailureReason: "token not found"}, nil
	}

	now := time.Now()
	if record.Status != authmodel.TokenStatusActive {
		return &authmodel.TokenVerificationResult{
			Valid: false, Status: record.Status, Token: record, FailureReason: "token status is not active"}, nil
	}
	if now.After(record.ExpiresAt.Add(time.Duration(req.AllowExpiredSkewSec) * time.Second)) {
		return &authmodel.TokenVerificationResult{
			Valid: false, Status: authmodel.TokenStatusExpired, Token: record, FailureReason: "token expired"}, nil
	}
	if len(req.ExpectedTypes) > 0 && !containsTokenType(req.ExpectedTypes, record.Type) {
		return &authmodel.TokenVerificationResult{
			Valid: false, Status: record.Status, Token: record, FailureReason: "unexpected token type",
		}, nil
	}

	identity := &authmodel.IdentityContext{
		Principal:   record.Principal,
		EntityType:  record.Principal.EntityType,
		EntityID:    record.Principal.EntityID,
		PrincipalID: record.PrincipalID,
		SessionID:   record.SessionID,
		TokenID:     record.ID,
		TokenType:   record.Type,
		Role:        record.RoleSnapshot,
		Scopes:      append([]string(nil), record.ScopeSnapshot...),
		ClientID:    record.ClientID,
		GatewayID:   record.GatewayID,
		IssuedAt:    record.IssuedAt,
		ExpiresAt:   record.ExpiresAt,
	}
	if claims != nil {
		identity.AuthMethod = claims.AuthMethod
		identity.SourceService = claims.SourceService
		identity.TargetService = claims.TargetService
		identity.TokenFamilyID = claims.FamilyID
	}

	return &authmodel.TokenVerificationResult{
		Valid:    true,
		Status:   record.Status,
		Identity: identity,
		Token:    record,
	}, nil
}

// RevokeToken 根据令牌ID或令牌家族ID撤销令牌。
func (s *TokenService) RevokeToken(ctx context.Context, req *authmodel.TokenRevokeRequest) error {
	if req == nil {
		return fmt.Errorf("token revoke request is nil")
	}

	if req.FamilyID != uuid.Nil {
		return s.RevokeTokenFamily(ctx, req.FamilyID.String(), req.RevokedBy)
	}

	if req.TokenID == uuid.Nil {
		return fmt.Errorf("token id or family id is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.byToken[req.TokenID]
	if !ok || record == nil {
		return nil
	}
	record.Status = authmodel.TokenStatusRevoked
	record.RevokedAt = time.Now()
	_ = s.updateTokenStatus(ctx, req.TokenID, authmodel.TokenStatusRevoked)

	return nil
}

// RevokeTokenFamily 根据令牌家族ID撤销该家族下的所有令牌。
func (s *TokenService) RevokeTokenFamily(ctx context.Context, familyID string, revokedBy string) error {
	if familyID == "" {
		return fmt.Errorf("family id is required")
	}

	parsed, err := uuid.Parse(familyID)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	family := s.byFamily[parsed]
	for _, token := range family {
		token.Status = authmodel.TokenStatusRevoked
		token.RevokedAt = time.Now()
		_ = s.updateTokenStatus(ctx, token.ID, authmodel.TokenStatusRevoked)
	}

	return nil
}

func defaultTTLByType(t authmodel.TokenType) int64 {
	switch t {
	case authmodel.TokenRefresh:
		return defaultRefreshTTLSeconds
	case authmodel.TokenService:
		return defaultServiceTTLSeconds
	case authmodel.TokenDownstream:
		return defaultGrantTTLSeconds
	default:
		return defaultAccessTTLSeconds
	}
}

func storageByType(t authmodel.TokenType) authmodel.TokenStorage {
	if t == authmodel.TokenRefresh {
		return authmodel.TokenStorageDatabase
	}
	return authmodel.TokenStorageCache
}

func buildRawToken(t authmodel.TokenType, id uuid.UUID) string {
	return fmt.Sprintf("%s.%s", string(t), id.String())
}

func containsTokenType(set []authmodel.TokenType, item authmodel.TokenType) bool {
	for _, v := range set {
		if v == item {
			return true
		}
	}
	return false
}

func (s *TokenService) persistTokenRecord(
	ctx context.Context, raw string, record *authmodel.TokenRecord, claims *authmodel.TokenClaims) error {

	if s.mysql == nil || record == nil {
		return nil
	}

	scopeJSON, _ := json.Marshal(record.ScopeSnapshot)
	_, err := s.mysql.Exec(ctx, `
INSERT INTO auth_token_records(
  id, raw_token, family_id, session_id, token_type, status, storage,
  principal_type, principal_id, parent_token_id, client_id, gateway_id,
  role_snapshot, scope_snapshot, issued_at, expires_at, last_validated_at, revoked_at
) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON DUPLICATE KEY UPDATE
  status=VALUES(status), storage=VALUES(storage), client_id=VALUES(client_id), gateway_id=VALUES(gateway_id),
  role_snapshot=VALUES(role_snapshot), scope_snapshot=VALUES(scope_snapshot), issued_at=VALUES(issued_at),
  expires_at=VALUES(expires_at), last_validated_at=VALUES(last_validated_at), revoked_at=VALUES(revoked_at)
`,
		record.ID.String(), raw, record.FamilyID.String(), record.SessionID.String(), string(record.Type), string(record.Status), string(record.Storage),
		string(record.Principal.EntityType), record.Principal.EntityID, nullableUUID(record.ParentTokenID), record.ClientID, record.GatewayID,
		record.RoleSnapshot, string(scopeJSON), record.IssuedAt, record.ExpiresAt, nullableTime(record.LastValidatedAt), nullableTime(record.RevokedAt),
	)
	if err != nil {
		return err
	}

	if claims == nil {
		return nil
	}

	scopesJSON, _ := json.Marshal(claims.Scopes)
	_, err = s.mysql.Exec(ctx, `
INSERT INTO auth_token_claims(
  token_id, issuer, audience, subject, token_type, entity_type, entity_id, principal_id,
  session_id, family_id, parent_id, role, scopes, auth_method,
  client_id, gateway_id, source_service, target_service, issued_at, expires_at
) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON DUPLICATE KEY UPDATE
  issuer=VALUES(issuer), audience=VALUES(audience), subject=VALUES(subject), token_type=VALUES(token_type),
  entity_type=VALUES(entity_type), entity_id=VALUES(entity_id), principal_id=VALUES(principal_id),
  session_id=VALUES(session_id), family_id=VALUES(family_id), parent_id=VALUES(parent_id),
  role=VALUES(role), scopes=VALUES(scopes), auth_method=VALUES(auth_method),
  client_id=VALUES(client_id), gateway_id=VALUES(gateway_id), source_service=VALUES(source_service),
  target_service=VALUES(target_service), issued_at=VALUES(issued_at), expires_at=VALUES(expires_at)
`,
		claims.TokenID.String(), claims.Issuer, claims.Audience, claims.Subject, string(claims.Type), string(claims.EntityType), claims.EntityID, claims.PrincipalID,
		claims.SessionID.String(), claims.FamilyID.String(), nullableUUID(claims.ParentID), claims.Role, string(scopesJSON), string(claims.AuthMethod),
		claims.ClientID, claims.GatewayID, claims.SourceService, claims.TargetService, claims.IssuedAt, claims.ExpiresAt,
	)
	return err
}

func (s *TokenService) updateTokenStatus(ctx context.Context, tokenID uuid.UUID, status authmodel.TokenStatus) error {
	if s.mysql == nil || tokenID == uuid.Nil {
		return nil
	}
	_, err := s.mysql.Exec(ctx, `UPDATE auth_token_records SET status=?, revoked_at=? WHERE id=?`, string(status), time.Now(), tokenID.String())
	return err
}

func (s *TokenService) cacheToken(ctx context.Context, raw string, record *authmodel.TokenRecord, claims *authmodel.TokenClaims) error {
	if s.redis == nil || raw == "" || record == nil {
		return nil
	}
	payload, err := json.Marshal(authmodel.TokenRecordCachePayload{Record: *record, Claims: claims})
	if err != nil {
		return err
	}
	ttl := time.Until(record.ExpiresAt)
	if ttl <= 0 {
		ttl = 5 * time.Second
	}
	return s.redis.Set(ctx, "auth:token:raw:"+raw, payload, ttl)
}

func (s *TokenService) loadTokenFromCache(
	ctx context.Context, raw string) (*authmodel.TokenRecord, *authmodel.TokenClaims, error) {

	if s.redis == nil {
		return nil, nil, fmt.Errorf("redis not configured")
	}
	str, err := s.redis.Get(ctx, "auth:token:raw:"+raw)
	if err != nil {
		if err == redis.Nil {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	var payload authmodel.TokenRecordCachePayload
	if err = json.Unmarshal([]byte(str), &payload); err != nil {
		return nil, nil, err
	}
	return &payload.Record, payload.Claims, nil
}

func (s *TokenService) loadTokenFromDB(
	ctx context.Context, raw string) (*authmodel.TokenRecord, *authmodel.TokenClaims, error) {

	if s.mysql == nil {
		return nil, nil, fmt.Errorf("mysql not configured")
	}
	var recRow authmodel.TokenRecordRow
	err := s.mysql.Get(ctx, &recRow, `
SELECT id, raw_token, family_id, session_id, token_type, status, storage, principal_type, principal_id,
       parent_token_id, client_id, gateway_id, role_snapshot, scope_snapshot, issued_at, expires_at,
       last_validated_at, revoked_at
FROM auth_token_records WHERE raw_token = ? LIMIT 1
`, raw)
	if err != nil {
		if repo.IsNotFound(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}

	record, err := mapTokenRecordRow(recRow)
	if err != nil {
		return nil, nil, err
	}

	var claimRow authmodel.TokenClaimsRow
	err = s.mysql.Get(ctx, &claimRow, `
SELECT token_id, issuer, audience, subject, token_type, entity_type, entity_id, principal_id,
       session_id, family_id, parent_id, role, scopes, auth_method, client_id, gateway_id,
       source_service, target_service, issued_at, expires_at
FROM auth_token_claims WHERE token_id = ? LIMIT 1
`, recRow.ID)
	if err != nil && !repo.IsNotFound(err) {
		return record, nil, err
	}
	if repo.IsNotFound(err) {
		return record, nil, nil
	}
	claims, cerr := mapTokenClaimsRow(claimRow)
	if cerr != nil {
		return record, nil, cerr
	}
	return record, claims, nil
}

func mapTokenRecordRow(row authmodel.TokenRecordRow) (*authmodel.TokenRecord, error) {
	id, err := uuid.Parse(row.ID)
	if err != nil {
		return nil, err
	}
	familyID, _ := uuid.Parse(row.FamilyID)
	sessionID, _ := uuid.Parse(row.SessionID)
	parentID, _ := uuid.Parse(row.ParentTokenID.String)
	var scopes []string
	_ = json.Unmarshal([]byte(row.ScopeSnapshot), &scopes)
	record := &authmodel.TokenRecord{
		ID:              id,
		FamilyID:        familyID,
		SessionID:       sessionID,
		Type:            authmodel.TokenType(row.Type),
		Status:          authmodel.TokenStatus(row.Status),
		Storage:         authmodel.TokenStorage(row.Storage),
		Principal:       authmodel.Principal{EntityType: authmodel.EntityType(row.PrincipalType), EntityID: row.PrincipalID},
		PrincipalID:     string(authmodel.EntityType(row.PrincipalType)) + ":" + row.PrincipalID,
		ParentTokenID:   parentID,
		ClientID:        row.ClientID,
		GatewayID:       row.GatewayID,
		RoleSnapshot:    row.RoleSnapshot,
		ScopeSnapshot:   scopes,
		IssuedAt:        row.IssuedAt,
		ExpiresAt:       row.ExpiresAt,
		LastValidatedAt: row.LastValidated.Time,
		RevokedAt:       row.RevokedAt.Time,
	}
	return record, nil
}

func mapTokenClaimsRow(row authmodel.TokenClaimsRow) (*authmodel.TokenClaims, error) {
	tokenID, _ := uuid.Parse(row.TokenID)
	sessionID, _ := uuid.Parse(row.SessionID)
	familyID, _ := uuid.Parse(row.FamilyID)
	parentID, _ := uuid.Parse(row.ParentID.String)
	var scopes []string
	_ = json.Unmarshal([]byte(row.Scopes), &scopes)
	return &authmodel.TokenClaims{
		Issuer:        row.Issuer,
		Audience:      row.Audience,
		Subject:       row.Subject,
		Type:          authmodel.TokenType(row.Type),
		EntityType:    authmodel.EntityType(row.EntityType),
		EntityID:      row.EntityID,
		PrincipalID:   row.PrincipalID,
		SessionID:     sessionID,
		TokenID:       tokenID,
		FamilyID:      familyID,
		ParentID:      parentID,
		Role:          row.Role,
		Scopes:        scopes,
		AuthMethod:    authmodel.AuthMethod(row.AuthMethod),
		ClientID:      row.ClientID,
		GatewayID:     row.GatewayID,
		SourceService: row.SourceService,
		TargetService: row.TargetService,
		IssuedAt:      row.IssuedAt,
		ExpiresAt:     row.ExpiresAt,
	}, nil
}

func nullableUUID(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id.String()
}

func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}
