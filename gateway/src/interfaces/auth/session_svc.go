package auth

import (
	"context"
	authmodel "gateway/src/models/auth"
)

// 服务模块侧（非认证中心）的会话管理服务接口，包含受限的会话访问方法。
type ISessionService interface {
	// GetSession 获取会话信息，sessionID 是会话标识符。
	GetSession(ctx context.Context, sessionID string) (*authmodel.Session, error)
	// TouchSession 更新会话信息，sessionID 是会话标识符，meta 是更新元数据。
	TouchSession(ctx context.Context, sessionID string, meta authmodel.SessionTouchMeta) error
	// ValidateSession 校验会话状态，用于出站调用前快速失败。
	ValidateSession(ctx context.Context, req *authmodel.SessionValidateRequest) (*authmodel.Session, error)
}
