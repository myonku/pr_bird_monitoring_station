package auth

import (
	"context"
	authmodel "gateway/src/models/auth"
)

// IBootstrapClient 定义外部调用认证中心冷启动认证流程的客户端接口，包含初始化挑战、验证挑战和查询冷启动阶段等方法。
type IBootstrapClient interface {
	// InitChallenge 向认证中心请求一次性挑战。
	InitChallenge(ctx context.Context, req *authmodel.ChallengeRequest) (*authmodel.ChallengePayload, error)
	// AuthenticateBootstrap 提交签名后的挑战并换取会话与令牌。
	AuthenticateBootstrap(ctx context.Context, req *authmodel.BootstrapAuthRequest) (*authmodel.BootstrapAuthResult, error)
	// GetBootstrapStage 返回当前模块冷启动状态，便于健康检查与启动门禁。
	GetBootstrapStage(ctx context.Context) (authmodel.BootstrapStage, error)
}
