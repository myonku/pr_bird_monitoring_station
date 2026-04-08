package auth

import (
	authmodel "certification_server/src/models/auth"
	"context"
)

// ISessionService 定义认证中心侧会话管理接口。
type ISessionService interface {
	// CreateSession 根据请求对象创建会话，返回会话信息。
	CreateSession(ctx context.Context, req *authmodel.SessionIssueRequest) (*authmodel.Session, error)
	// GetSession 查询会话信息，返回会话对象。
	GetSession(ctx context.Context, sessionID string) (*authmodel.Session, error)
	// TouchSession 更新会话信息，通常用于延长会话有效期或更新会话元数据。
	TouchSession(ctx context.Context, sessionID string, meta authmodel.SessionTouchMeta) error
	// ValidateSession 校验会话状态，确保会话有效且未被撤销。
	ValidateSession(ctx context.Context, req *authmodel.SessionValidateRequest) (*authmodel.Session, error)

	// RevokeSession 撤销会话，更新会话状态以拒绝后续使用。
	RevokeSession(ctx context.Context, req *authmodel.SessionRevokeRequest) error
	// RevokePrincipalSessions 根据认证主体标识撤销相关会话，通常用于强制用户下线。
	RevokePrincipalSessions(ctx context.Context, principalID string, reason string, revokedBy string) error
}
