package interfaces

import (
	"context"
	"gateway/src/models"
)

// 会话服务接口定义。Session 由认证中心颁发，包含认证实体的身份信息和权限信息。
// 网关通过会话服务获取会话信息，实现会话管理和会话亲和。
type ISessionService interface {
	// GetSession 获取会话信息，sessionID 是会话标识符。
	GetSession(ctx context.Context, sessionID string) (*models.Session, error)
	// TouchSession 更新会话信息，sessionID 是会话标识符，meta 是更新元数据。
	TouchSession(ctx context.Context, sessionID string, meta models.SessionTouchMeta) error
}
