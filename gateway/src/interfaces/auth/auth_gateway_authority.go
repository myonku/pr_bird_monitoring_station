package auth

import (
	"context"
	authmodel "gateway/src/models/auth"
)

// IAuthGatewayAuthorityClient 定义网关到认证中心统一鉴权门面的远端调用接口。
// Gateway 仅做转发，不在本地管理会话/令牌/挑战状态。
type IAuthGatewayAuthorityClient interface {
	InitChallenge(ctx context.Context, req *authmodel.ChallengeRequest) (*authmodel.ChallengePayload, error)
	AuthenticateBootstrap(ctx context.Context, req *authmodel.BootstrapAuthRequest) (*authmodel.BootstrapAuthResult, error)
	GetBootstrapStage(ctx context.Context, entityType authmodel.EntityType, entityID string) (authmodel.BootstrapStage, error)

	AuthenticateByPassword(ctx context.Context, req *authmodel.UserPasswordAuthRequest) (*authmodel.UserPasswordAuthResult, error)
	RefreshByUserSession(ctx context.Context, req *authmodel.TokenRefreshRequest) (*authmodel.TokenBundle, error)
	VerifyToken(ctx context.Context, req *authmodel.TokenVerifyRequest) (*authmodel.TokenVerificationResult, error)
	RevokeToken(ctx context.Context, req *authmodel.TokenRevokeRequest) error
	RevokeUserSession(ctx context.Context, req *authmodel.SessionRevokeRequest) error
	ValidateSession(ctx context.Context, req *authmodel.SessionValidateRequest) (*authmodel.Session, error)

	IssueDownstreamGrant(ctx context.Context, req *authmodel.DownstreamGrantRequest) (*authmodel.DownstreamAccessGrant, error)
}
