package common

import (
	"context"

	authmodel "certification_server/src/models/auth"
)

// ITokenManager 定义令牌管理相关操作。
type ITokenManager interface {
	// IssueToken 根据指定的请求信息颁发新的令牌。
	IssueToken(ctx context.Context, req *authmodel.TokenIssueRequest) (*authmodel.IssuedToken, error)
	// IssueTokenBundle 根据会话信息和请求参数颁发新的令牌包，包含访问令牌和刷新令牌等。
	IssueTokenBundle(ctx context.Context, session *authmodel.Session, req *authmodel.TokenIssueRequest) (*authmodel.TokenBundle, error)
	// RefreshTokenBundle 刷新令牌包，通常用于获取新的访问令牌和刷新令牌。
	RefreshTokenBundle(ctx context.Context, req *authmodel.TokenRefreshRequest) (*authmodel.TokenBundle, error)
	// 通过指定的验证请求校验令牌的有效性和相关信息。
	VerifyToken(ctx context.Context, req *authmodel.TokenVerifyRequest) (*authmodel.TokenVerificationResult, error)
	// 撤销指定的令牌。
	RevokeToken(ctx context.Context, req *authmodel.TokenRevokeRequest) error
	// 根据用户会话信息撤销令牌包，适用于用户主动刷新令牌的场景。
	RevokeTokenFamily(ctx context.Context, familyID string, revokedBy string) error
}
