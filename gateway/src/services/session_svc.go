package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gateway/src"
	"gateway/src/repo"
	"gateway/src/types"

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
	ctx context.Context, session types.GatewaySession, ttl time.Duration) error {

	if s.redis == nil {
		return errors.New("redis client is nil")
	}
	if session.ID == uuid.Nil {
		return errors.New("session id is required")
	}
	if ttl <= 0 {
		ttl = s.defaultTTL
	}
	if ttl <= 0 {
		return errors.New("session ttl must be greater than 0")
	}

	payload, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}

	return s.redis.Set(ctx, s.sessionKey(session.ID), payload, ttl)
}

// GetSession 获取会话信息。
func (s *SessionService) GetSession(
	ctx context.Context, sessionID uuid.UUID) (types.GatewaySession, error) {

	if s.redis == nil {
		return types.GatewaySession{}, errors.New("redis client is nil")
	}
	if sessionID == uuid.Nil {
		return types.GatewaySession{}, errors.New("session id is required")
	}

	raw, err := s.redis.Get(ctx, s.sessionKey(sessionID))
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return types.GatewaySession{}, fmt.Errorf("session %s not found", sessionID.String())
		}
		return types.GatewaySession{}, err
	}

	var session types.GatewaySession
	if err = json.Unmarshal([]byte(raw), &session); err != nil {
		return types.GatewaySession{}, fmt.Errorf("unmarshal session: %w", err)
	}
	return session, nil
}

// DeleteSession 删除会话。
func (s *SessionService) DeleteSession(ctx context.Context, sessionID uuid.UUID) error {
	if s.redis == nil {
		return errors.New("redis client is nil")
	}
	if sessionID == uuid.Nil {
		return errors.New("session id is required")
	}
	_, err := s.redis.Del(ctx, s.sessionKey(sessionID))
	return err
}

// TTL 获取会话剩余时间。
func (s *SessionService) TTL(ctx context.Context, sessionID uuid.UUID) (time.Duration, error) {
	if s.redis == nil {
		return 0, errors.New("redis client is nil")
	}
	if sessionID == uuid.Nil {
		return 0, errors.New("session id is required")
	}
	return s.redis.TTL(ctx, s.sessionKey(sessionID))
}

// RefreshSession 刷新会话过期时间。
func (s *SessionService) RefreshSession(ctx context.Context, sessionID uuid.UUID, ttl time.Duration) error {
	if s.redis == nil {
		return errors.New("redis client is nil")
	}
	if sessionID == uuid.Nil {
		return errors.New("session id is required")
	}
	if ttl <= 0 {
		return errors.New("ttl must be greater than 0")
	}
	_, err := s.redis.Expire(ctx, s.sessionKey(sessionID), ttl)
	return err
}

func (s *SessionService) sessionKey(sessionID uuid.UUID) string {
	return fmt.Sprintf("%s:%s", s.keyPrefix, sessionID.String())
}
