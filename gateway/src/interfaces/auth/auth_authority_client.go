package auth

import (
	"context"
	authmodel "gateway/src/models/auth"
)

// IAuthAuthorityClient 定义模块直连认证中心的统一鉴权门面调用接口。
// 该接口仅表达“调用认证中心能力”，不表示“经网关中转内部流量”。
type IAuthAuthorityClient interface {
	InitChallenge(ctx context.Context, req *authmodel.ChallengeRequest) (*authmodel.ChallengePayload, error)
	AuthenticateBootstrap(ctx context.Context, req *authmodel.BootstrapAuthRequest) (*authmodel.BootstrapAuthResult, error)
	GetBootstrapStage(ctx context.Context, entityType authmodel.EntityType, entityID string) (authmodel.BootstrapStage, error)

	AuthenticateByPassword(ctx context.Context, req *authmodel.UserPasswordAuthRequest) (*authmodel.UserPasswordAuthResult, error)
	RefreshModuleToken(ctx context.Context, req *authmodel.TokenRefreshRequest) (*authmodel.TokenBundle, error)
	RevokeModuleSession(ctx context.Context, req *authmodel.SessionRevokeRequest) error

	// 历史兼容：客户端用户会话续期。
	RefreshByUserSession(ctx context.Context, req *authmodel.TokenRefreshRequest) (*authmodel.TokenBundle, error)
	VerifyToken(ctx context.Context, req *authmodel.TokenVerifyRequest) (*authmodel.TokenVerificationResult, error)
	RevokeToken(ctx context.Context, req *authmodel.TokenRevokeRequest) error
	RevokeUserSession(ctx context.Context, req *authmodel.SessionRevokeRequest) error
	ValidateSession(ctx context.Context, req *authmodel.SessionValidateRequest) (*authmodel.Session, error)

	IssueDownstreamGrant(ctx context.Context, req *authmodel.DownstreamGrantRequest) (*authmodel.DownstreamAccessGrant, error)
}
