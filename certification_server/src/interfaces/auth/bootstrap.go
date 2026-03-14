package auth

import (
	authmodel "certification_server/src/models/auth"
	"context"
)

// IBootstrapService 定义了认证中心侧冷启动认证流程的接口，包含初始化挑战、验证挑战和查询冷启动阶段等方法。
type IBootstrapService interface {
	// InitChallenge 根据请求对象生成挑战信息，返回挑战载荷。
	InitChallenge(ctx context.Context, req *authmodel.ChallengeRequest) (*authmodel.ChallengePayload, error)
	// AuthenticateBootstrap 根据请求对象验证挑战信息，返回认证结果。
	AuthenticateBootstrap(ctx context.Context, req *authmodel.BootstrapAuthRequest) (*authmodel.BootstrapAuthResult, error)
	// GetBootstrapStage 返回实体 bootstrap 当前阶段。
	GetBootstrapStage(ctx context.Context, entityType authmodel.EntityType, entityID string) (authmodel.BootstrapStage, error)
}
