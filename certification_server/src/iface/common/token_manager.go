package common

import (
	"context"

	authmodel "certification_server/src/models/auth"

	"github.com/google/uuid"
)

// TokenIssueRequest is the token issue contract for common auth managers.
type TokenIssueRequest struct {
	Principal authmodel.Principal

	TokenType authmodel.TokenType
	SessionID uuid.UUID
	FamilyID  uuid.UUID

	Audience string
	Role     string
	Scopes   []string

	AuthMethod authmodel.AuthMethod

	ClientID      string
	GatewayID     string
	SourceService string
	TargetService string

	ParentTokenID uuid.UUID
	TTLSec        int64
}

// TokenRefreshRequest is the token refresh contract for common auth managers.
type TokenRefreshRequest struct {
	RefreshToken string

	ClientID  string
	GatewayID string
	SourceIP  string
	UserAgent string

	RequestID string
	TraceID   string
}

// TokenVerifyRequest is the token verify contract for common auth managers.
type TokenVerifyRequest struct {
	RawToken string

	ExpectedTypes    []authmodel.TokenType
	ExpectedAudience string
	RequireScopes    []string

	SourceService string
	TargetService string

	AllowExpiredSkewSec int64
}

// TokenRevokeRequest is the token revoke contract for common auth managers.
type TokenRevokeRequest struct {
	TokenID   uuid.UUID
	FamilyID  uuid.UUID
	SessionID uuid.UUID

	Reason    string
	RevokedBy string

	RequestID string
	TraceID   string
}

// ITokenManager 定义令牌管理相关操作。
type ITokenManager interface {
	// IssueToken 根据指定的请求信息颁发新的令牌。
	IssueToken(ctx context.Context, req *TokenIssueRequest) (*authmodel.IssuedToken, error)
	// IssueTokenBundle 根据会话信息和请求参数颁发新的令牌包，包含访问令牌和刷新令牌等。
	IssueTokenBundle(ctx context.Context, session *authmodel.Session, req *TokenIssueRequest) (*authmodel.TokenBundle, error)
	// RefreshTokenBundle 刷新令牌包，通常用于获取新的访问令牌和刷新令牌。
	RefreshTokenBundle(ctx context.Context, req *TokenRefreshRequest) (*authmodel.TokenBundle, error)
	// 通过指定的验证请求校验令牌的有效性和相关信息。
	VerifyToken(ctx context.Context, req *TokenVerifyRequest) (*authmodel.TokenVerificationResult, error)
	// 撤销指定的令牌。
	RevokeToken(ctx context.Context, req *TokenRevokeRequest) error
	// 根据用户会话信息撤销令牌包，适用于用户主动刷新令牌的场景。
	RevokeTokenFamily(ctx context.Context, familyID string, revokedBy string) error
}
