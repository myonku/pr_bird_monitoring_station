package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	interfaces "certification_server/src/interfaces/auth"
	commseciface "certification_server/src/interfaces/commsec"
	authmodel "certification_server/src/models/auth"
	modelsystem "certification_server/src/models/system"
	"certification_server/src/repo"
	"certification_server/src/utils"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

var _ interfaces.IBootstrapService = (*BootstrapService)(nil)

// BootstrapService 提供冷启动 challenge 认证流程实现。
type BootstrapService struct {
	mu sync.RWMutex

	challenges map[uuid.UUID]*authmodel.ChallengePayload
	stages     map[string]authmodel.BootstrapStage

	mysql *repo.MySQLClient
	redis *repo.RedisClient

	sessionSvc interfaces.ISessionService
	tokenSvc   interfaces.ITokenService
	keySvc     commseciface.ISecretKeyService
	crypto     *utils.CryptoUtils
}

// NewBootstrapService 创建冷启动认证服务实例。
func NewBootstrapService(
	mysql *repo.MySQLClient,
	redis *repo.RedisClient,
	sessionSvc interfaces.ISessionService,
	tokenSvc interfaces.ITokenService,
	keySvc commseciface.ISecretKeyService,
	crypto *utils.CryptoUtils,
) *BootstrapService {
	if crypto == nil {
		crypto = &utils.CryptoUtils{}
	}
	return &BootstrapService{
		challenges: make(map[uuid.UUID]*authmodel.ChallengePayload),
		stages:     make(map[string]authmodel.BootstrapStage),
		mysql:      mysql,
		redis:      redis,
		sessionSvc: sessionSvc,
		tokenSvc:   tokenSvc,
		keySvc:     keySvc,
		crypto:     crypto,
	}
}

// InitChallenge 生成一个新的挑战，记录挑战状态为 Challenging，并返回挑战载荷给调用方。
func (s *BootstrapService) InitChallenge(
	ctx context.Context, req *authmodel.ChallengeRequest) (*authmodel.ChallengePayload, error) {

	if req == nil {
		return nil, &modelsystem.ErrChallengeRequestNil
	}
	if req.EntityID == "" || req.KeyID == "" {
		return nil, &modelsystem.ErrEntityIDAndKeyIDRequired
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
	// challenge/stage 属于短期冷启动状态，默认仅缓存。
	_ = s.cacheChallenge(ctx, payload)
	_ = s.persistStage(ctx, principalID, authmodel.BootstrapStageChallenging)

	return payload, nil
}

// AuthenticateBootstrap 验证挑战响应的合法性，签发会话与令牌，并返回认证结果。
func (s *BootstrapService) AuthenticateBootstrap(
	ctx context.Context, req *authmodel.BootstrapAuthRequest) (*authmodel.BootstrapAuthResult, error) {

	if req == nil {
		return nil, &modelsystem.ErrBootstrapAuthRequestNil
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
	if stored == nil {
		return nil, &modelsystem.ErrChallengeNotFound
	}
	if time.Now().After(stored.ExpiresAt) {
		return nil, &modelsystem.ErrChallengeExpired
	}
	if req.Signed.ChallengeID != stored.ChallengeID || req.Signed.KeyID != stored.KeyID {
		return nil, &modelsystem.ErrChallengeResponseMismatch
	}

	if s.keySvc != nil {
		lookup, err := s.keySvc.GetPublicKeyByKeyID(ctx, stored.KeyID)
		if err != nil {
			return nil, err
		}
		if !lookup.Found {
			return nil, &modelsystem.ErrPublicKeyNotFoundForKeyID
		}
		sigAlgo := req.Signed.SignatureAlgorithm
		if sigAlgo == "" {
			sigAlgo = lookup.Key.SignatureAlgorithm
		}
		if sigAlgo == "" {
			return nil, &modelsystem.ErrSignatureAlgorithmRequired
		}
		if req.Signed.SignatureAlgorithm != "" && lookup.Key.SignatureAlgorithm != "" &&
			req.Signed.SignatureAlgorithm != lookup.Key.SignatureAlgorithm {
			return nil, &modelsystem.ErrSignatureAlgorithmMismatch
		}
		signPayload := buildBootstrapSignaturePayload(stored)
		if verifyErr := s.crypto.VerifyByAlgorithm(
			string(sigAlgo),
			signPayload,
			req.Signed.Signature,
			[]byte(lookup.Key.PublicKeyPEM)); verifyErr != nil {
			return nil, fmt.Errorf("challenge signature verify failed: %w", verifyErr)
		}
	}

	principal := authmodel.Principal{EntityType: stored.EntityType, EntityID: stored.EntityID}
	principalID := principal.PrincipalID()

	s.mu.Lock()
	s.stages[principalID] = authmodel.BootstrapStageAuthenticating
	s.mu.Unlock()
	_ = s.persistStage(ctx, principalID, authmodel.BootstrapStageAuthenticating)

	if s.sessionSvc == nil || s.tokenSvc == nil {
		return nil, &modelsystem.ErrBootstrapDepsNotReady
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
		return authmodel.BootstrapStageUninitialized, &modelsystem.ErrEntityIDRequired
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
	if !ok {
		return authmodel.BootstrapStageUninitialized, nil
	}

	return stage, nil
}

func (s *BootstrapService) persistChallenge(ctx context.Context, payload *authmodel.ChallengePayload) error {
	if payload == nil {
		return nil
	}
	return nil
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
		return nil, &modelsystem.ErrRedisNotConfigured
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
	_ = ctx
	_ = challengeID
	return nil, nil
}

func (s *BootstrapService) deleteChallenge(ctx context.Context, challengeID uuid.UUID) error {
	if s.redis != nil {
		_, _ = s.redis.Del(ctx, "auth:bootstrap:challenge:"+challengeID.String())
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
	return nil
}

func (s *BootstrapService) loadStageFromCache(ctx context.Context, principalID string) (authmodel.BootstrapStage, error) {
	if s.redis == nil {
		return "", &modelsystem.ErrRedisNotConfigured
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
	_ = ctx
	_ = principalID
	return "", nil
}

// buildBootstrapSignaturePayload 构建挑战签名的原始载荷，供调用方签名使用。
func buildBootstrapSignaturePayload(challenge *authmodel.ChallengePayload) []byte {
	if challenge == nil {
		return []byte("")
	}
	parts := []string{
		challenge.ChallengeID.String(),
		challenge.Issuer,
		challenge.Audience,
		string(challenge.EntityType),
		challenge.EntityID,
		challenge.KeyID,
		challenge.Nonce,
		challenge.IssuedAt.UTC().Format(time.RFC3339Nano),
		challenge.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}
	return []byte(strings.Join(parts, "|"))
}
