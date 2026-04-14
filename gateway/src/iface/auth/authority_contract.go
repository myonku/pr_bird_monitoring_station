package auth

import (
	authmodel "gateway/src/models/auth"

	"github.com/google/uuid"
)

// TokenRefreshRequest 定义网关侧刷新令牌请求。
type TokenRefreshRequest struct {
	RefreshToken string

	ClientID  string
	GatewayID string
	SourceIP  string
	UserAgent string

	RequestID string
	TraceID   string
}

// TokenVerifyRequest 定义网关侧令牌校验请求。
type TokenVerifyRequest struct {
	RawToken string

	ExpectedTypes    []authmodel.TokenType
	ExpectedAudience string
	RequireScopes    []string

	SourceService string
	TargetService string

	AllowExpiredSkewSec int64
}

// TokenRevokeRequest 定义网关侧令牌撤销请求。
type TokenRevokeRequest struct {
	TokenID   uuid.UUID
	FamilyID  uuid.UUID
	SessionID uuid.UUID

	Reason    string
	RevokedBy string

	RequestID string
	TraceID   string
}

// SessionValidateRequest 定义网关侧会话校验请求。
type SessionValidateRequest struct {
	SessionID     uuid.UUID
	PrincipalID   string
	RequireActive bool
	MinVersion    int64
}
