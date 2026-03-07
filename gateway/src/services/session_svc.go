package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gateway/src"
	"gateway/src/models"
	"gateway/src/repo"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

var _ src.ISessionService = (*SessionService)(nil)

// SessionService 基于 Redis 实现会话存储。
type SessionService struct {
	redis      *repo.RedisClient
	keyPrefix  string
	defaultTTL time.Duration
}

// NewSessionService 创建 Session 服务。
func NewSessionService(
	redisClient *repo.RedisClient,
	keyPrefix string,
	defaultTTL time.Duration,
) src.ISessionService {
	if keyPrefix == "" {
		keyPrefix = "gateway:session"
	}
	return &SessionService{redis: redisClient, keyPrefix: keyPrefix, defaultTTL: defaultTTL}
}

// SetSession 写入或更新会话信息。
func (s *SessionService) SetSession(
	ctx context.Context, session models.GatewaySession, ttl time.Duration) error {

	if s.redis == nil {
		return &models.ErrNilRedisClient
	}
	if session.ID == uuid.Nil {
		return &models.ErrSessionIdRequired
	}
	if ttl <= 0 {
		ttl = s.defaultTTL
	}
	if ttl <= 0 {
		return &models.ErrNegativeSessionTTL
	}

	payload, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}

	return s.redis.Set(ctx, s.sessionKey(session.ID), payload, ttl)
}

// GetSession 获取会话信息。
func (s *SessionService) GetSession(
	ctx context.Context, sessionID uuid.UUID) (models.GatewaySession, error) {

	if s.redis == nil {
		return models.GatewaySession{}, &models.ErrNilRedisClient
	}
	if sessionID == uuid.Nil {
		return models.GatewaySession{}, &models.ErrSessionIdRequired
	}

	raw, err := s.redis.Get(ctx, s.sessionKey(sessionID))
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return models.GatewaySession{}, &models.ErrorSessionNotFound
		}
		return models.GatewaySession{}, err
	}

	var session models.GatewaySession
	if err = json.Unmarshal([]byte(raw), &session); err != nil {
		return models.GatewaySession{}, fmt.Errorf("unmarshal session: %w", err)
	}
	return session, nil
}

// DeleteSession 删除会话。
func (s *SessionService) DeleteSession(ctx context.Context, sessionID uuid.UUID) error {
	if s.redis == nil {
		return &models.ErrNilRedisClient
	}
	if sessionID == uuid.Nil {
		return &models.ErrSessionIdRequired
	}
	_, err := s.redis.Del(ctx, s.sessionKey(sessionID))
	return err
}

// TTL 获取会话剩余时间。
func (s *SessionService) TTL(ctx context.Context, sessionID uuid.UUID) (time.Duration, error) {
	if s.redis == nil {
		return 0, &models.ErrNilRedisClient
	}
	if sessionID == uuid.Nil {
		return 0, &models.ErrSessionIdRequired
	}
	return s.redis.TTL(ctx, s.sessionKey(sessionID))
}

// RefreshSession 刷新会话过期时间。
func (s *SessionService) RefreshSession(ctx context.Context, sessionID uuid.UUID, ttl time.Duration) error {
	if s.redis == nil {
		return &models.ErrNilRedisClient
	}
	if sessionID == uuid.Nil {
		return &models.ErrSessionIdRequired
	}
	if ttl <= 0 {
		return &models.ErrNegativeSessionTTL
	}
	_, err := s.redis.Expire(ctx, s.sessionKey(sessionID), ttl)
	return err
}

func (s *SessionService) sessionKey(sessionID uuid.UUID) string {
	return fmt.Sprintf("%s:%s", s.keyPrefix, sessionID.String())
}
