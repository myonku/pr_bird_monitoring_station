package orchestration

import (
	authmodel "certification_server/src/models/auth"
	commonmodel "certification_server/src/models/common"
	"context"
)

// IAuthGatewayOrchestrator 定义认证中心统一鉴权门面编排接口。
// 该接口作为认证中心对外鉴权入口，供 gRPC handler 统一调用。
type IAuthGatewayOrchestrator interface {
	// Bootstrap 相关能力。
	InitChallenge(ctx context.Context, req *authmodel.ChallengeRequest) (*authmodel.ChallengePayload, error)
	AuthenticateBootstrap(ctx context.Context, req *authmodel.BootstrapAuthRequest) (*authmodel.BootstrapAuthResult, error)
	GetBootstrapStage(ctx context.Context, entityType commonmodel.EntityType, entityID string) (authmodel.BootstrapStage, error)

	// 用户认证与令牌能力。
	AuthenticateByPassword(ctx context.Context, req *authmodel.UserPasswordAuthRequest) (*authmodel.UserPasswordAuthResult, error)
	RefreshModuleToken(ctx context.Context, req *authmodel.TokenRefreshRequest) (*authmodel.TokenBundle, error)
	RevokeModuleSession(ctx context.Context, req *authmodel.SessionRevokeRequest) error

	// 历史兼容：客户端用户会话续期。
	RefreshByUserSession(ctx context.Context, req *authmodel.TokenRefreshRequest) (*authmodel.TokenBundle, error)
	VerifyToken(ctx context.Context, req *authmodel.TokenVerifyRequest) (*authmodel.TokenVerificationResult, error)
	RevokeToken(ctx context.Context, req *authmodel.TokenRevokeRequest) error
	RevokeUserSession(ctx context.Context, req *authmodel.SessionRevokeRequest) error

	// 会话与下游授权能力。
	ValidateSession(ctx context.Context, req *authmodel.SessionValidateRequest) (*authmodel.Session, error)
	IssueDownstreamGrant(ctx context.Context, req *authmodel.DownstreamGrantRequest) (*authmodel.DownstreamAccessGrant, error)
}
