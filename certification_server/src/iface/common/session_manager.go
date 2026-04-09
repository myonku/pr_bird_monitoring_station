package common

import (
	"context"
	"time"

	authmodel "certification_server/src/models/auth"

	"github.com/google/uuid"
)

// SessionIssueRequest 表示会话创建请求的契约。
type SessionIssueRequest struct {
	Principal authmodel.Principal
	Role      string
	Scopes    []string

	AuthMethod authmodel.AuthMethod

	ClientID  string
	GatewayID string
	SourceIP  string
	UserAgent string

	ExpiresAt time.Time
}

// SessionValidateRequest 表示会话校验请求的契约。
type SessionValidateRequest struct {
	SessionID     uuid.UUID
	PrincipalID   string
	RequireActive bool
	MinVersion    int64
}

// SessionRevokeRequest 是会话撤销请求的契约，包含单会话撤销和全局登出两种场景。
type SessionRevokeRequest struct {
	SessionID   uuid.UUID
	PrincipalID string

	Reason    string
	RevokedBy string

	RequestID string
	TraceID   string
}

// ISessionManager 定义会话管理相关操作。
type ISessionManager interface {
	// CreateSession 创建新的会话。
	CreateSession(ctx context.Context, req *SessionIssueRequest) (*authmodel.Session, error)
	// GetSession 获取指定ID的会话信息。
	GetSession(ctx context.Context, sessionID string) (*authmodel.Session, error)
	// TouchSession 更新会话的活跃时间戳和相关元信息。
	TouchSession(ctx context.Context, sessionID string, meta authmodel.SessionTouchMeta) error
	// ValidateSession 校验会话的有效性。
	ValidateSession(ctx context.Context, req *SessionValidateRequest) (*authmodel.Session, error)
	// RevokeSession 撤销指定的会话。
	RevokeSession(ctx context.Context, req *SessionRevokeRequest) error
	// RevokePrincipalSessions 根据主体ID撤销相关会话，适用于用户或模块的全局登出等场景。
	RevokePrincipalSessions(ctx context.Context, principalID string, reason string, revokedBy string) error
}
