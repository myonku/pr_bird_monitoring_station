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

var _ authif.ISessionService = (*SessionService)(nil)

// SessionService 提供网关侧会话快照管理。
type SessionService struct {
	mu           sync.RWMutex
	sessionsByID map[uuid.UUID]*authmodel.Session
	redis        *repo.RedisClient
}

func NewSessionService(redis ...*repo.RedisClient) *SessionService {
	var redisClient *repo.RedisClient
	if len(redis) > 0 {
		redisClient = redis[0]
	}
	return &SessionService{
		sessionsByID: make(map[uuid.UUID]*authmodel.Session),
		redis:        redisClient,
	}
}

// UpsertSessionFromBootstrap 将 bootstrap 返回的会话写入本地缓存。
func (s *SessionService) UpsertSessionFromBootstrap(session *authmodel.Session) {
	if s == nil || session == nil || session.ID == uuid.Nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	clone := *session
	clone.ScopeSnapshot = append([]string(nil), session.ScopeSnapshot...)
	s.sessionsByID[session.ID] = &clone
	_ = s.cacheSession(context.Background(), &clone)
}

func (s *SessionService) GetSession(ctx context.Context, sessionID string) (*authmodel.Session, error) {
	_ = ctx
	if s == nil {
		return nil, &modelsystem.ErrSessionServiceNotConfigured
	}
	id, err := uuid.Parse(sessionID)
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	session := s.sessionsByID[id]
	s.mu.RUnlock()
	if session == nil {
		cached, cacheErr := s.loadSessionFromCache(ctx, id)
		if cacheErr == nil && cached != nil {
			session = cached
			s.trackSession(cached)
		}
	}
	if session == nil {
		return nil, &modelsystem.ErrSessionNotFound
	}

	clone := *session
	clone.ScopeSnapshot = append([]string(nil), session.ScopeSnapshot...)
	return &clone, nil
}

func (s *SessionService) TouchSession(ctx context.Context, sessionID string, meta authmodel.SessionTouchMeta) error {
	_ = ctx
	if s == nil {
		return &modelsystem.ErrSessionServiceNotConfigured
	}
	id, err := uuid.Parse(sessionID)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.sessionsByID[id]
	if session == nil {
		return &modelsystem.ErrSessionNotFound
	}
	if session.Status != authmodel.SessionActive {
		return &modelsystem.ErrSessionNotActive
	}

	now := time.Now()
	if meta.SourceIP != "" {
		session.LastSeenIP = meta.SourceIP
	}
	if meta.UserAgent != "" {
		session.UserAgent = meta.UserAgent
	}
	if meta.ClientID != "" {
		session.ClientID = meta.ClientID
	}
	if meta.GatewayID != "" {
		session.GatewayID = meta.GatewayID
	}
	session.LastSeenAt = now
	session.UpdatedAt = now
	session.Version++
	_ = s.cacheSession(ctx, session)
	return nil
}

func (s *SessionService) ValidateSession(ctx context.Context, req *authmodel.SessionValidateRequest) (*authmodel.Session, error) {
	_ = ctx
	if s == nil {
		return nil, &modelsystem.ErrSessionServiceNotConfigured
	}
	if req == nil {
		return nil, &modelsystem.ErrSessionValidateRequestNil
	}

	s.mu.RLock()
	session := s.sessionsByID[req.SessionID]
	s.mu.RUnlock()
	if session == nil {
		cached, cacheErr := s.loadSessionFromCache(ctx, req.SessionID)
		if cacheErr == nil && cached != nil {
			session = cached
			s.trackSession(cached)
		}
	}
	if session == nil {
		return nil, &modelsystem.ErrSessionNotFound
	}
	if req.PrincipalID != "" && req.PrincipalID != session.PrincipalID {
		return nil, &modelsystem.ErrSessionPrincipalMismatch
	}
	if req.RequireActive && session.Status != authmodel.SessionActive {
		return nil, &modelsystem.ErrSessionNotActive
	}
	if req.MinVersion > 0 && session.Version < req.MinVersion {
		return nil, &modelsystem.ErrSessionVersionStale
	}
	if !session.ExpiresAt.IsZero() && time.Now().After(session.ExpiresAt) {
		return nil, &modelsystem.ErrSessionExpired
	}

	clone := *session
	clone.ScopeSnapshot = append([]string(nil), session.ScopeSnapshot...)
	return &clone, nil
}

func (s *SessionService) cacheSession(ctx context.Context, session *authmodel.Session) error {
	if s.redis == nil || session == nil {
		return nil
	}
	payload, err := json.Marshal(session)
	if err != nil {
		return err
	}
	ttl := time.Until(session.ExpiresAt)
	if ttl <= 0 {
		ttl = 5 * time.Second
	}
	return s.redis.Set(ctx, "auth:session:id:"+session.ID.String(), payload, ttl)
}

func (s *SessionService) loadSessionFromCache(ctx context.Context, id uuid.UUID) (*authmodel.Session, error) {
	if s.redis == nil {
		return nil, &modelsystem.ErrNilRedisClient
	}
	raw, err := s.redis.Get(ctx, "auth:session:id:"+id.String())
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}
	var session authmodel.Session
	if err := json.Unmarshal([]byte(raw), &session); err != nil {
		return nil, err
	}
	return &session, nil
}

func (s *SessionService) trackSession(session *authmodel.Session) {
	if session == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessionsByID[session.ID] = session
}
