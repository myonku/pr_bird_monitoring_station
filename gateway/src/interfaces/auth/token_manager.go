package auth

import (
	"context"
	authmodel "gateway/src/models/auth"
)

// ITokenManager 定义了服务侧令牌管理的接口，包含获取、刷新、验证和撤销令牌的方法。
type ITokenManager interface {
	// GetAccessToken 返回当前可用 access token。
	GetAccessToken(ctx context.Context) (*authmodel.IssuedToken, error)
	// Refresh 根据 refresh token 刷新 access token（必要时轮换 refresh token）。
	Refresh(ctx context.Context, req *authmodel.TokenRefreshRequest) (*authmodel.TokenBundle, error)
	// Verify 校验令牌并返回认证上下文。
	Verify(ctx context.Context, req *authmodel.TokenVerifyRequest) (*authmodel.TokenVerificationResult, error)
	// Revoke 本地或远端撤销令牌状态。
	Revoke(ctx context.Context, req *authmodel.TokenRevokeRequest) error
}
