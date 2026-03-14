package auth

import (
	authmodel "certification_server/src/models/auth"
	"context"
)

// IAuthCenterService 聚合认证中心对外核心能力。
// 整合了认证中心的引导认证、令牌管理、会话管理和下游授权等接口，供网关或其他服务通过认证中心客户端访问。
type IAuthCenterService interface {
	// Bootstrap 相关接口
	InitChallenge(ctx context.Context, req *authmodel.ChallengeRequest) (*authmodel.ChallengePayload, error)
	AuthenticateBootstrap(ctx context.Context, req *authmodel.BootstrapAuthRequest) (*authmodel.BootstrapAuthResult, error)

	// Token 相关接口
	IssueTokenBundle(ctx context.Context, session *authmodel.Session, req *authmodel.TokenIssueRequest) (*authmodel.TokenBundle, error)
	RefreshTokenBundle(ctx context.Context, req *authmodel.TokenRefreshRequest) (*authmodel.TokenBundle, error)
	VerifyToken(ctx context.Context, req *authmodel.TokenVerifyRequest) (*authmodel.TokenVerificationResult, error)
	RevokeToken(ctx context.Context, req *authmodel.TokenRevokeRequest) error

	// Session 相关接口
	GetSession(ctx context.Context, sessionID string) (*authmodel.Session, error)
	TouchSession(ctx context.Context, sessionID string, meta authmodel.SessionTouchMeta) error
	ValidateSession(ctx context.Context, req *authmodel.SessionValidateRequest) (*authmodel.Session, error)
	RevokeSession(ctx context.Context, req *authmodel.SessionRevokeRequest) error

	// 根据认证实体信息颁发下游访问授权，返回授权结果。
	IssueDownstreamGrant(ctx context.Context, req *authmodel.DownstreamGrantRequest) (*authmodel.DownstreamAccessGrant, error)
}
