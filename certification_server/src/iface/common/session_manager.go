package common

import (
	"context"

	authmodel "certification_server/src/models/auth"
)

// ISessionManager 定义会话管理相关操作。
type ISessionManager interface {
	// CreateSession 创建新的会话。
	CreateSession(ctx context.Context, req *authmodel.SessionIssueRequest) (*authmodel.Session, error)
	// GetSession 获取指定ID的会话信息。
	GetSession(ctx context.Context, sessionID string) (*authmodel.Session, error)
	// TouchSession 更新会话的活跃时间戳和相关元信息。
	TouchSession(ctx context.Context, sessionID string, meta authmodel.SessionTouchMeta) error
	// ValidateSession 校验会话的有效性。
	ValidateSession(ctx context.Context, req *authmodel.SessionValidateRequest) (*authmodel.Session, error)
	// RevokeSession 撤销指定的会话。
	RevokeSession(ctx context.Context, req *authmodel.SessionRevokeRequest) error
	// RevokePrincipalSessions 根据主体ID撤销相关会话，适用于用户或模块的全局登出等场景。
	RevokePrincipalSessions(ctx context.Context, principalID string, reason string, revokedBy string) error
}
