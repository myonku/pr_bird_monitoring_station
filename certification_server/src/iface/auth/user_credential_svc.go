package auth

import (
	authmodel "certification_server/src/models/auth"
	"context"
)

// IUserCredentialAuthService 定义用户名/密码认证入口与用户会话续期能力。
type IUserCredentialAuthService interface {
	// AuthenticateByPassword 校验用户凭据并签发 session + token bundle。
	AuthenticateByPassword(
		ctx context.Context,
		req *authmodel.UserPasswordAuthRequest,
	) (*authmodel.UserPasswordAuthResult, error)

	// RefreshByUserSession 使用 refresh token 对用户会话进行续期。
	RefreshByUserSession(
		ctx context.Context,
		req *authmodel.TokenRefreshRequest,
	) (*authmodel.TokenBundle, error)

	// RevokeUserSession 撤销用户会话，触发后续重新登录。
	RevokeUserSession(ctx context.Context, req *authmodel.SessionRevokeRequest) error
}
