package auth

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	iface "certification_server/src/iface/auth"
	authmodel "certification_server/src/models/auth"
	modelsystem "certification_server/src/models/system"
	"certification_server/src/repo"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

var _ iface.ISessionService = (*SessionService)(nil)

// SessionService 提供认证中心会话管理的内存实现。
type SessionService struct {
	mu sync.RWMutex

	redis *repo.RedisClient

	byID        map[uuid.UUID]*authmodel.Session
	byPrincipal map[string]map[uuid.UUID]*authmodel.Session
}

// NewSessionService 创建会话服务实例。
func NewSessionService(redis *repo.RedisClient) *SessionService {
	return &SessionService{
		redis:       redis,
		byID:        make(map[uuid.UUID]*authmodel.Session),
		byPrincipal: make(map[string]map[uuid.UUID]*authmodel.Session),
	}
}

// CreateSession 根据认证结果创建新的会话记录。
func (s *SessionService) CreateSession(
	ctx context.Context, req *authmodel.SessionIssueRequest) (*authmodel.Session, error) {

	if req == nil {
		return nil, &modelsystem.ErrSessionIssueRequestNil
	}
	if req.Principal.PrincipalID() == "" {
		return nil, &modelsystem.ErrPrincipalRequired
	}

	now := time.Now()
	expiresAt := req.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = now.Add(24 * time.Hour)
	}

	session := &authmodel.Session{
		ID:            uuid.New(),
		Principal:     req.Principal,
		EntityType:    req.Principal.EntityType,
		EntityID:      req.Principal.EntityID,
		PrincipalID:   req.Principal.PrincipalID(),
		Status:        authmodel.SessionActive,
		AuthMethod:    req.AuthMethod,
		CreatedByIP:   req.SourceIP,
		LastSeenIP:    req.SourceIP,
		UserAgent:     req.UserAgent,
		ClientID:      req.ClientID,
		GatewayID:     req.GatewayID,
		ScopeSnapshot: append([]string(nil), req.Scopes...),
		RoleSnapshot:  req.Role,
		TokenFamilyID: uuid.New(),
		CreatedAt:     now,
		UpdatedAt:     now,
		LastSeenAt:    now,
		NextRefreshAt: now.Add(30 * time.Minute),
		ExpiresAt:     expiresAt,
		Version:       1,
	}

	s.mu.Lock()
	s.byID[session.ID] = session
	if s.byPrincipal[session.PrincipalID] == nil {
		s.byPrincipal[session.PrincipalID] = make(map[uuid.UUID]*authmodel.Session)
	}
	s.byPrincipal[session.PrincipalID][session.ID] = session
	s.mu.Unlock()

	// 会话属于运行时状态，默认仅写缓存，不做数据库持久化。
	_ = s.cacheSession(ctx, session)

	return cloneSession(session), nil
}

// GetSession 根据会话ID查询会话记录。
func (s *SessionService) GetSession(ctx context.Context, sessionID string) (*authmodel.Session, error) {
	id, err := uuid.Parse(sessionID)
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	session := s.byID[id]
	s.mu.RUnlock()
	if session == nil && s.redis != nil {
		cached, cacheErr := s.loadSessionFromCache(ctx, id)
		if cacheErr == nil && cached != nil {
			session = cached
			s.trackSession(cached)
		}
	}
	if session == nil {
		return nil, &modelsystem.ErrSessionNotFound
	}

	return cloneSession(session), nil
}

// TouchSession 更新会话的最后访问信息。
func (s *SessionService) TouchSession(
	ctx context.Context, sessionID string, meta authmodel.SessionTouchMeta) error {

	id, err := uuid.Parse(sessionID)
	if err != nil {
		return err
	}

	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	session := s.byID[id]
	if session == nil {
		return &modelsystem.ErrSessionNotFound
	}
	if session.Status != authmodel.SessionActive {
		return &modelsystem.ErrSessionNotActive
	}

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

// ValidateSession 验证会话的有效性和状态。
func (s *SessionService) ValidateSession(
	ctx context.Context, req *authmodel.SessionValidateRequest) (*authmodel.Session, error) {

	if req == nil {
		return nil, &modelsystem.ErrSessionValidateRequestNil
	}

	s.mu.RLock()
	session := s.byID[req.SessionID]
	s.mu.RUnlock()
	if session == nil && s.redis != nil {
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
	if time.Now().After(session.ExpiresAt) {
		return nil, &modelsystem.ErrSessionExpired
	}

	return cloneSession(session), nil
}

// RevokeSession 根据会话ID撤销会话。
func (s *SessionService) RevokeSession(ctx context.Context, req *authmodel.SessionRevokeRequest) error {
	if req == nil {
		return &modelsystem.ErrSessionRevokeRequestNil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	session := s.byID[req.SessionID]
	if session == nil {
		return nil
	}
	session.Status = authmodel.SessionRevoked
	session.RevokedAt = time.Now()
	session.UpdatedAt = time.Now()
	session.Version++
	_ = s.cacheSession(ctx, session)

	return nil
}

// RevokePrincipalSessions 根据主体ID撤销该主体的所有会话。
func (s *SessionService) RevokePrincipalSessions(
	ctx context.Context, principalID string, reason string, revokedBy string) error {

	if principalID == "" {
		return &modelsystem.ErrPrincipalIDRequired
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	sessions := s.byPrincipal[principalID]
	now := time.Now()
	for _, session := range sessions {
		session.Status = authmodel.SessionRevoked
		session.RevokedAt = now
		session.UpdatedAt = now
		session.Version++
		_ = s.cacheSession(ctx, session)
	}

	return nil
}

// cloneSession 创建会话记录的副本以避免外部修改内部状态。
func cloneSession(s *authmodel.Session) *authmodel.Session {
	if s == nil {
		return nil
	}
	out := *s
	out.ScopeSnapshot = append([]string(nil), s.ScopeSnapshot...)
	return &out
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
		return nil, &modelsystem.ErrRedisNotConfigured
	}
	str, err := s.redis.Get(ctx, "auth:session:id:"+id.String())
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}
	var session authmodel.Session
	if err = json.Unmarshal([]byte(str), &session); err != nil {
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
	s.byID[session.ID] = session
	if s.byPrincipal[session.PrincipalID] == nil {
		s.byPrincipal[session.PrincipalID] = make(map[uuid.UUID]*authmodel.Session)
	}
	s.byPrincipal[session.PrincipalID][session.ID] = session
}
