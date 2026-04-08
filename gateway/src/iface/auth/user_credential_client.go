package auth

import (
	"context"
	authmodel "gateway/src/models/auth"
)

// IUserCredentialAuthClient 定义网关向认证中心转发客户端认证请求的接口。
type IUserCredentialAuthClient interface {
	// AuthenticateByPassword 转发用户名/密码登录请求。
	AuthenticateByPassword(
		ctx context.Context,
		req *authmodel.UserPasswordAuthRequest,
	) (*authmodel.UserPasswordAuthResult, error)

	// RefreshByUserSession 转发 refresh token 续期请求。
	RefreshByUserSession(
		ctx context.Context,
		req *authmodel.TokenRefreshRequest,
	) (*authmodel.TokenBundle, error)

	// VerifyUserToken 转发用户 access token 校验请求。
	VerifyUserToken(
		ctx context.Context,
		req *authmodel.TokenVerifyRequest,
	) (*authmodel.TokenVerificationResult, error)

	// RevokeUserToken 转发用户令牌撤销请求。
	RevokeUserToken(ctx context.Context, req *authmodel.TokenRevokeRequest) error

	// RevokeUserSession 转发用户会话撤销请求。
	RevokeUserSession(ctx context.Context, req *authmodel.SessionRevokeRequest) error
}
