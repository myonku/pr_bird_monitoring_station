package auth

import (
	authmodel "certification_server/src/models/auth"
	"context"
)

// ITokenService 定义令牌签发、刷新、校验与撤销接口。
type ITokenService interface {
	// IssueToken 根据认证结果颁发访问令牌，返回令牌信息。
	IssueToken(ctx context.Context, req *authmodel.TokenIssueRequest) (*authmodel.IssuedToken, error)
	// IssueTokenBundle 根据会话信息颁发访问令牌，返回令牌信息和相关元数据。
	IssueTokenBundle(ctx context.Context, session *authmodel.Session, req *authmodel.TokenIssueRequest) (*authmodel.TokenBundle, error)

	// RefreshToken 根据刷新请求刷新访问令牌，必要时轮换刷新令牌，返回新的令牌信息。
	RefreshTokenBundle(ctx context.Context, req *authmodel.TokenRefreshRequest) (*authmodel.TokenBundle, error)
	// VerifyToken 校验访问令牌的有效性和权限，返回认证上下文。
	VerifyToken(ctx context.Context, req *authmodel.TokenVerifyRequest) (*authmodel.TokenVerificationResult, error)

	// RevokeToken 撤销访问令牌，更新令牌状态以拒绝后续使用。
	RevokeToken(ctx context.Context, req *authmodel.TokenRevokeRequest) error
	// RevokeTokenFamily 根据令牌族标识撤销相关令牌，通常用于强制用户下线。
	RevokeTokenFamily(ctx context.Context, familyID string, revokedBy string) error
}
