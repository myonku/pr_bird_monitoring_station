package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	interfaces "certification_server/src/interfaces/auth"
	commseciface "certification_server/src/interfaces/commsec"
	authmodel "certification_server/src/models/auth"
	"certification_server/src/repo"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

var _ interfaces.IBootstrapService = (*BootstrapService)(nil)

// BootstrapService 提供冷启动 challenge 认证流程实现。
// 签名验证与信任链策略后续可按正式密钥治理方案增强。
type BootstrapService struct {
	mu sync.RWMutex

	challenges map[uuid.UUID]*authmodel.ChallengePayload
	stages     map[string]authmodel.BootstrapStage

	mysql *repo.MySQLClient
	redis *repo.RedisClient

	sessionSvc interfaces.ISessionService
	tokenSvc   interfaces.ITokenService
	keySvc     commseciface.ISecretKeyService
}

func NewBootstrapService(
	mysql *repo.MySQLClient,
	redis *repo.RedisClient,
	sessionSvc interfaces.ISessionService,
	tokenSvc interfaces.ITokenService,
	keySvc commseciface.ISecretKeyService,
) *BootstrapService {
	return &BootstrapService{
		challenges: make(map[uuid.UUID]*authmodel.ChallengePayload),
		stages:     make(map[string]authmodel.BootstrapStage),
		mysql:      mysql,
		redis:      redis,
		sessionSvc: sessionSvc,
		tokenSvc:   tokenSvc,
		keySvc:     keySvc,
	}
}

// InitChallenge 生成一个新的挑战，记录挑战状态为 Challenging，并返回挑战载荷给调用方。
func (s *BootstrapService) InitChallenge(
	ctx context.Context, req *authmodel.ChallengeRequest) (*authmodel.ChallengePayload, error) {

	if req == nil {
		return nil, fmt.Errorf("challenge request is nil")
	}
	if req.EntityID == "" || req.KeyID == "" {
		return nil, fmt.Errorf("entity id and key id are required")
	}

	ttlSec := req.TTLSec
	if ttlSec <= 0 {
		ttlSec = 120
	}

	now := time.Now()
	payload := &authmodel.ChallengePayload{
		ChallengeID: uuid.New(),
		Issuer:      "certification_server",
		Audience:    req.Audience,
		EntityType:  req.EntityType,
		EntityID:    req.EntityID,
		KeyID:       req.KeyID,
		Nonce:       uuid.NewString(),
		IssuedAt:    now,
		ExpiresAt:   now.Add(time.Duration(ttlSec) * time.Second),
	}

	principalID := authmodel.Principal{EntityType: req.EntityType, EntityID: req.EntityID}.PrincipalID()

	s.mu.Lock()
	s.challenges[payload.ChallengeID] = payload
	s.stages[principalID] = authmodel.BootstrapStageChallenging
	s.mu.Unlock()
	_ = s.persistChallenge(ctx, payload)
	_ = s.cacheChallenge(ctx, payload)
	_ = s.persistStage(ctx, principalID, authmodel.BootstrapStageChallenging)

	return payload, nil
}

// AuthenticateBootstrap 验证挑战响应的合法性，签发会话与令牌，并返回认证结果。
func (s *BootstrapService) AuthenticateBootstrap(
	ctx context.Context, req *authmodel.BootstrapAuthRequest) (*authmodel.BootstrapAuthResult, error) {

	if req == nil {
		return nil, fmt.Errorf("bootstrap auth request is nil")
	}

	s.mu.RLock()
	stored := s.challenges[req.Challenge.ChallengeID]
	s.mu.RUnlock()
	if stored == nil && s.redis != nil {
		cached, cacheErr := s.loadChallengeFromCache(ctx, req.Challenge.ChallengeID)
		if cacheErr == nil {
			stored = cached
		}
	}
	if stored == nil && s.mysql != nil {
		dbPayload, dbErr := s.loadChallengeFromDB(ctx, req.Challenge.ChallengeID)
		if dbErr == nil {
			stored = dbPayload
		}
	}
	if stored == nil {
		return nil, fmt.Errorf("challenge not found")
	}
	if time.Now().After(stored.ExpiresAt) {
		return nil, fmt.Errorf("challenge expired")
	}
	if req.Signed.ChallengeID != stored.ChallengeID || req.Signed.KeyID != stored.KeyID {
		return nil, fmt.Errorf("challenge response mismatch")
	}

	if s.keySvc != nil {
		lookup, err := s.keySvc.GetPublicKeyByKeyID(ctx, stored.KeyID)
		if err != nil {
			return nil, err
		}
		if !lookup.Found {
			return nil, fmt.Errorf("public key not found for key id")
		}
		// TODO: 使用 lookup.Key.PublicKeyPEM 与 req.Signed.Signature 完成严格签名验签。
	}

	principal := authmodel.Principal{EntityType: stored.EntityType, EntityID: stored.EntityID}
	principalID := principal.PrincipalID()

	s.mu.Lock()
	s.stages[principalID] = authmodel.BootstrapStageAuthenticating
	s.mu.Unlock()
	_ = s.persistStage(ctx, principalID, authmodel.BootstrapStageAuthenticating)

	if s.sessionSvc == nil || s.tokenSvc == nil {
		return nil, fmt.Errorf("bootstrap dependencies are not ready")
	}

	session, err := s.sessionSvc.CreateSession(ctx, &authmodel.SessionIssueRequest{
		Principal:  principal,
		Role:       req.Role,
		Scopes:     append([]string(nil), req.Scopes...),
		AuthMethod: authmodel.AuthMethodServiceSecret,
		ExpiresAt:  time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		return nil, err
	}

	bundle, err := s.tokenSvc.IssueTokenBundle(ctx, session, &authmodel.TokenIssueRequest{
		Principal: principal,
		Audience:  stored.Audience,
		Role:      req.Role,
		Scopes:    append([]string(nil), req.Scopes...),
	})
	if err != nil {
		return nil, err
	}

	now := time.Now()
	identity := &authmodel.IdentityContext{
		Principal:   principal,
		EntityType:  principal.EntityType,
		EntityID:    principal.EntityID,
		PrincipalID: principalID,
		SessionID:   session.ID,
		Role:        req.Role,
		Scopes:      append([]string(nil), req.Scopes...),
		AuthMethod:  authmodel.AuthMethodServiceSecret,
		IssuedAt:    now,
		ExpiresAt:   now.Add(24 * time.Hour),
	}
	if bundle != nil && bundle.AccessToken != nil {
		identity.TokenID = bundle.AccessToken.Claims.TokenID
		identity.TokenFamilyID = bundle.AccessToken.Claims.FamilyID
		identity.TokenType = bundle.AccessToken.Type
		identity.ExpiresAt = bundle.AccessToken.Claims.ExpiresAt
	}

	s.mu.Lock()
	s.stages[principalID] = authmodel.BootstrapStageReady
	delete(s.challenges, stored.ChallengeID)
	s.mu.Unlock()
	_ = s.persistStage(ctx, principalID, authmodel.BootstrapStageReady)
	_ = s.deleteChallenge(ctx, stored.ChallengeID)

	result := &authmodel.BootstrapAuthResult{
		Stage:           authmodel.BootstrapStageReady,
		Identity:        identity,
		Session:         session,
		ActiveCommKeyID: stored.KeyID,
		IssuedAt:        now,
		ExpiresAt:       identity.ExpiresAt,
	}
	if bundle != nil {
		result.Tokens = *bundle
	}

	return result, nil
}

// GetBootstrapStage 查询指定实体的冷启动认证阶段，返回阶段枚举值。
func (s *BootstrapService) GetBootstrapStage(
	ctx context.Context, entityType authmodel.EntityType, entityID string) (authmodel.BootstrapStage, error) {

	if entityID == "" {
		return authmodel.BootstrapStageUninitialized, fmt.Errorf("entity id is required")
	}

	principalID := authmodel.Principal{EntityType: entityType, EntityID: entityID}.PrincipalID()

	s.mu.RLock()
	stage, ok := s.stages[principalID]
	s.mu.RUnlock()
	if !ok && s.redis != nil {
		cached, cacheErr := s.loadStageFromCache(ctx, principalID)
		if cacheErr == nil && cached != "" {
			stage = cached
			ok = true
		}
	}
	if !ok && s.mysql != nil {
		dbStage, dbErr := s.loadStageFromDB(ctx, principalID)
		if dbErr == nil && dbStage != "" {
			stage = dbStage
			ok = true
		}
	}
	if !ok {
		return authmodel.BootstrapStageUninitialized, nil
	}

	return stage, nil
}

func (s *BootstrapService) persistChallenge(ctx context.Context, payload *authmodel.ChallengePayload) error {
	if s.mysql == nil || payload == nil {
		return nil
	}
	_, err := s.mysql.Exec(ctx, `
INSERT INTO auth_bootstrap_challenges(
 challenge_id, issuer, audience, entity_type, entity_id, key_id, nonce, issued_at, expires_at
) VALUES(?,?,?,?,?,?,?,?,?)
ON DUPLICATE KEY UPDATE
 issuer=VALUES(issuer), audience=VALUES(audience), entity_type=VALUES(entity_type), entity_id=VALUES(entity_id),
 key_id=VALUES(key_id), nonce=VALUES(nonce), issued_at=VALUES(issued_at), expires_at=VALUES(expires_at)
`, payload.ChallengeID.String(), payload.Issuer, payload.Audience, string(payload.EntityType), payload.EntityID, payload.KeyID, payload.Nonce, payload.IssuedAt, payload.ExpiresAt)
	return err
}

func (s *BootstrapService) cacheChallenge(ctx context.Context, payload *authmodel.ChallengePayload) error {
	if s.redis == nil || payload == nil {
		return nil
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	ttl := time.Until(payload.ExpiresAt)
	if ttl <= 0 {
		ttl = 5 * time.Second
	}
	return s.redis.Set(ctx, "auth:bootstrap:challenge:"+payload.ChallengeID.String(), body, ttl)
}

func (s *BootstrapService) loadChallengeFromCache(ctx context.Context, challengeID uuid.UUID) (*authmodel.ChallengePayload, error) {
	if s.redis == nil {
		return nil, fmt.Errorf("redis not configured")
	}
	raw, err := s.redis.Get(ctx, "auth:bootstrap:challenge:"+challengeID.String())
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}
	var payload authmodel.ChallengePayload
	if err = json.Unmarshal([]byte(raw), &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

func (s *BootstrapService) loadChallengeFromDB(ctx context.Context, challengeID uuid.UUID) (*authmodel.ChallengePayload, error) {
	if s.mysql == nil {
		return nil, fmt.Errorf("mysql not configured")
	}
	var row struct {
		ChallengeID string    `db:"challenge_id"`
		Issuer      string    `db:"issuer"`
		Audience    string    `db:"audience"`
		EntityType  string    `db:"entity_type"`
		EntityID    string    `db:"entity_id"`
		KeyID       string    `db:"key_id"`
		Nonce       string    `db:"nonce"`
		IssuedAt    time.Time `db:"issued_at"`
		ExpiresAt   time.Time `db:"expires_at"`
	}
	err := s.mysql.Get(ctx, &row, `
SELECT challenge_id, issuer, audience, entity_type, entity_id, key_id, nonce, issued_at, expires_at
FROM auth_bootstrap_challenges WHERE challenge_id = ? LIMIT 1
`, challengeID.String())
	if err != nil {
		if repo.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	id, _ := uuid.Parse(row.ChallengeID)
	return &authmodel.ChallengePayload{
		ChallengeID: id,
		Issuer:      row.Issuer,
		Audience:    row.Audience,
		EntityType:  authmodel.EntityType(row.EntityType),
		EntityID:    row.EntityID,
		KeyID:       row.KeyID,
		Nonce:       row.Nonce,
		IssuedAt:    row.IssuedAt,
		ExpiresAt:   row.ExpiresAt,
	}, nil
}

func (s *BootstrapService) deleteChallenge(ctx context.Context, challengeID uuid.UUID) error {
	if s.redis != nil {
		_, _ = s.redis.Del(ctx, "auth:bootstrap:challenge:"+challengeID.String())
	}
	if s.mysql != nil {
		_, _ = s.mysql.Exec(ctx, `DELETE FROM auth_bootstrap_challenges WHERE challenge_id = ?`, challengeID.String())
	}
	return nil
}

func (s *BootstrapService) persistStage(ctx context.Context, principalID string, stage authmodel.BootstrapStage) error {
	if principalID == "" {
		return nil
	}
	if s.redis != nil {
		_ = s.redis.Set(ctx, "auth:bootstrap:stage:"+principalID, string(stage), 24*time.Hour)
	}
	if s.mysql != nil {
		_, _ = s.mysql.Exec(ctx, `
INSERT INTO auth_bootstrap_stages(principal_id, stage, updated_at)
VALUES(?,?,?)
ON DUPLICATE KEY UPDATE stage=VALUES(stage), updated_at=VALUES(updated_at)
`, principalID, string(stage), time.Now())
	}
	return nil
}

func (s *BootstrapService) loadStageFromCache(ctx context.Context, principalID string) (authmodel.BootstrapStage, error) {
	if s.redis == nil {
		return "", fmt.Errorf("redis not configured")
	}
	raw, err := s.redis.Get(ctx, "auth:bootstrap:stage:"+principalID)
	if err != nil {
		if err == redis.Nil {
			return "", nil
		}
		return "", err
	}
	return authmodel.BootstrapStage(raw), nil
}

func (s *BootstrapService) loadStageFromDB(ctx context.Context, principalID string) (authmodel.BootstrapStage, error) {
	if s.mysql == nil {
		return "", fmt.Errorf("mysql not configured")
	}
	var row struct {
		Stage string `db:"stage"`
	}
	err := s.mysql.Get(ctx, &row, `SELECT stage FROM auth_bootstrap_stages WHERE principal_id = ? LIMIT 1`, principalID)
	if err != nil {
		if repo.IsNotFound(err) {
			return "", nil
		}
		return "", err
	}
	return authmodel.BootstrapStage(row.Stage), nil
}
