package auth

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	authif "gateway/src/interfaces/auth"
	authmodel "gateway/src/models/auth"
	modelsystem "gateway/src/models/system"
	"gateway/src/repo"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

var _ authif.IBootstrapClient = (*MemoryBootstrapClient)(nil)

// MemoryBootstrapClient 提供开发阶段可替换的 bootstrap 客户端实现。
type MemoryBootstrapClient struct {
	mu sync.RWMutex

	challenges map[uuid.UUID]*authmodel.ChallengePayload
	stages     map[string]authmodel.BootstrapStage
	lastPID    string
	redis      *repo.RedisClient
}

func NewMemoryBootstrapClient(redis ...*repo.RedisClient) *MemoryBootstrapClient {
	var redisClient *repo.RedisClient
	if len(redis) > 0 {
		redisClient = redis[0]
	}
	return &MemoryBootstrapClient{
		challenges: make(map[uuid.UUID]*authmodel.ChallengePayload),
		stages:     make(map[string]authmodel.BootstrapStage),
		redis:      redisClient,
	}
}

func (c *MemoryBootstrapClient) InitChallenge(
	ctx context.Context, req *authmodel.ChallengeRequest,
) (*authmodel.ChallengePayload, error) {
	_ = ctx
	if req == nil {
		return nil, &modelsystem.ErrChallengeRequestNil
	}
	if req.EntityID == "" || req.KeyID == "" {
		return nil, &modelsystem.ErrEntityIDAndKeyIDRequired
	}
	ttl := req.TTLSec
	if ttl <= 0 {
		ttl = 120
	}
	payload := &authmodel.ChallengePayload{
		ChallengeID: uuid.New(),
		Issuer:      "certification_server",
		Audience:    req.Audience,
		EntityType:  req.EntityType,
		EntityID:    req.EntityID,
		KeyID:       req.KeyID,
		Nonce:       uuid.NewString(),
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(time.Duration(ttl) * time.Second),
	}
	principalID := authmodel.Principal{EntityType: req.EntityType, EntityID: req.EntityID}.PrincipalID()
	c.mu.Lock()
	c.challenges[payload.ChallengeID] = payload
	c.stages[principalID] = authmodel.BootstrapStageChallenging
	c.lastPID = principalID
	c.mu.Unlock()
	_ = c.cacheChallenge(ctx, payload)
	_ = c.cacheStage(ctx, principalID, authmodel.BootstrapStageChallenging)
	return payload, nil
}

func (c *MemoryBootstrapClient) AuthenticateBootstrap(
	ctx context.Context, req *authmodel.BootstrapAuthRequest,
) (*authmodel.BootstrapAuthResult, error) {
	_ = ctx
	if req == nil {
		return nil, &modelsystem.ErrBootstrapAuthRequestNil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	challenge := c.challenges[req.Challenge.ChallengeID]
	if challenge == nil {
		cached, cacheErr := c.loadChallengeFromCache(ctx, req.Challenge.ChallengeID)
		if cacheErr == nil {
			challenge = cached
		}
	}
	if challenge == nil {
		return nil, &modelsystem.ErrChallengeNotFound
	}
	if time.Now().After(challenge.ExpiresAt) {
		return nil, &modelsystem.ErrChallengeExpired
	}
	if req.Signed.KeyID != challenge.KeyID {
		return nil, &modelsystem.ErrChallengeResponseMismatch
	}

	principal := authmodel.Principal{EntityType: challenge.EntityType, EntityID: challenge.EntityID}
	now := time.Now()
	session := &authmodel.Session{
		ID:            uuid.New(),
		Principal:     principal,
		EntityType:    principal.EntityType,
		EntityID:      principal.EntityID,
		PrincipalID:   principal.PrincipalID(),
		Status:        authmodel.SessionActive,
		AuthMethod:    authmodel.AuthMethodServiceSecret,
		ScopeSnapshot: append([]string(nil), req.Scopes...),
		RoleSnapshot:  req.Role,
		TokenFamilyID: uuid.New(),
		CreatedAt:     now,
		UpdatedAt:     now,
		LastSeenAt:    now,
		NextRefreshAt: now.Add(30 * time.Minute),
		ExpiresAt:     now.Add(24 * time.Hour),
		Version:       1,
	}
	access := &authmodel.IssuedToken{
		Raw:     string(authmodel.TokenAccess) + "." + uuid.NewString(),
		Type:    authmodel.TokenAccess,
		Storage: authmodel.TokenStorageCache,
		TTLSec:  600,
		Claims: authmodel.TokenClaims{
			Issuer:      "certification_server",
			Audience:    challenge.Audience,
			Subject:     principal.EntityID,
			Type:        authmodel.TokenAccess,
			EntityType:  principal.EntityType,
			EntityID:    principal.EntityID,
			PrincipalID: principal.PrincipalID(),
			SessionID:   session.ID,
			TokenID:     uuid.New(),
			FamilyID:    session.TokenFamilyID,
			Role:        req.Role,
			Scopes:      append([]string(nil), req.Scopes...),
			AuthMethod:  authmodel.AuthMethodServiceSecret,
			IssuedAt:    now,
			ExpiresAt:   now.Add(10 * time.Minute),
		},
	}
	refresh := &authmodel.IssuedToken{
		Raw:     string(authmodel.TokenRefresh) + "." + uuid.NewString(),
		Type:    authmodel.TokenRefresh,
		Storage: authmodel.TokenStorageDatabase,
		TTLSec:  86400,
		Claims: authmodel.TokenClaims{
			Issuer:      "certification_server",
			Audience:    challenge.Audience,
			Subject:     principal.EntityID,
			Type:        authmodel.TokenRefresh,
			EntityType:  principal.EntityType,
			EntityID:    principal.EntityID,
			PrincipalID: principal.PrincipalID(),
			SessionID:   session.ID,
			TokenID:     uuid.New(),
			FamilyID:    session.TokenFamilyID,
			Role:        req.Role,
			Scopes:      append([]string(nil), req.Scopes...),
			AuthMethod:  authmodel.AuthMethodServiceSecret,
			IssuedAt:    now,
			ExpiresAt:   now.Add(24 * time.Hour),
		},
	}
	identity := &authmodel.IdentityContext{
		Principal:     principal,
		EntityType:    principal.EntityType,
		EntityID:      principal.EntityID,
		PrincipalID:   principal.PrincipalID(),
		SessionID:     session.ID,
		TokenID:       access.Claims.TokenID,
		TokenFamilyID: session.TokenFamilyID,
		TokenType:     authmodel.TokenAccess,
		Role:          req.Role,
		Scopes:        append([]string(nil), req.Scopes...),
		AuthMethod:    authmodel.AuthMethodServiceSecret,
		IssuedAt:      now,
		ExpiresAt:     access.Claims.ExpiresAt,
	}

	principalID := principal.PrincipalID()
	c.stages[principalID] = authmodel.BootstrapStageReady
	c.lastPID = principalID
	delete(c.challenges, req.Challenge.ChallengeID)
	_ = c.deleteChallenge(ctx, req.Challenge.ChallengeID)
	_ = c.cacheStage(ctx, principalID, authmodel.BootstrapStageReady)

	return &authmodel.BootstrapAuthResult{
		Stage:           authmodel.BootstrapStageReady,
		Identity:        identity,
		Session:         session,
		Tokens:          authmodel.TokenBundle{AccessToken: access, RefreshToken: refresh},
		ActiveCommKeyID: challenge.KeyID,
		IssuedAt:        now,
		ExpiresAt:       access.Claims.ExpiresAt,
	}, nil
}

func (c *MemoryBootstrapClient) GetBootstrapStage(ctx context.Context) (authmodel.BootstrapStage, error) {
	c.mu.RLock()
	lastPID := c.lastPID
	defer c.mu.RUnlock()
	if lastPID != "" {
		if stage, ok := c.stages[lastPID]; ok {
			return stage, nil
		}
		cached, cacheErr := c.loadStageFromCache(ctx, lastPID)
		if cacheErr == nil && cached != "" {
			return cached, nil
		}
	}
	for _, stage := range c.stages {
		return stage, nil
	}
	if c.redis != nil {
		raw, err := c.redis.Get(ctx, "auth:bootstrap:stage:last")
		if err == nil && raw != "" {
			return authmodel.BootstrapStage(raw), nil
		}
		if err != nil && err != redis.Nil {
			return "", err
		}
	}
	return authmodel.BootstrapStageUninitialized, nil
}

func (c *MemoryBootstrapClient) cacheChallenge(ctx context.Context, payload *authmodel.ChallengePayload) error {
	if c.redis == nil || payload == nil {
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
	return c.redis.Set(ctx, "auth:bootstrap:challenge:"+payload.ChallengeID.String(), body, ttl)
}

func (c *MemoryBootstrapClient) loadChallengeFromCache(ctx context.Context, challengeID uuid.UUID) (*authmodel.ChallengePayload, error) {
	if c.redis == nil {
		return nil, &modelsystem.ErrNilRedisClient
	}
	raw, err := c.redis.Get(ctx, "auth:bootstrap:challenge:"+challengeID.String())
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}
	var payload authmodel.ChallengePayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

func (c *MemoryBootstrapClient) deleteChallenge(ctx context.Context, challengeID uuid.UUID) error {
	if c.redis == nil {
		return nil
	}
	_, err := c.redis.Del(ctx, "auth:bootstrap:challenge:"+challengeID.String())
	return err
}

func (c *MemoryBootstrapClient) cacheStage(ctx context.Context, principalID string, stage authmodel.BootstrapStage) error {
	if c.redis == nil || principalID == "" {
		return nil
	}
	if err := c.redis.Set(ctx, "auth:bootstrap:stage:"+principalID, string(stage), 24*time.Hour); err != nil {
		return err
	}
	_ = c.redis.Set(ctx, "auth:bootstrap:stage:last", string(stage), 24*time.Hour)
	_ = c.redis.Set(ctx, "auth:bootstrap:stage:last_principal", principalID, 24*time.Hour)
	return nil
}

func (c *MemoryBootstrapClient) loadStageFromCache(ctx context.Context, principalID string) (authmodel.BootstrapStage, error) {
	if c.redis == nil {
		return "", &modelsystem.ErrNilRedisClient
	}
	raw, err := c.redis.Get(ctx, "auth:bootstrap:stage:"+principalID)
	if err != nil {
		if err == redis.Nil {
			return "", nil
		}
		return "", err
	}
	return authmodel.BootstrapStage(raw), nil
}
