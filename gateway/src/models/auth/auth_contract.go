package auth

import (
	"time"

	commsec "gateway/src/models/commsec"

	"github.com/google/uuid"
)

// TokenIssueRequest 表示签发任意类型令牌的统一参数。
type TokenIssueRequest struct {
	Principal Principal

	TokenType TokenType
	SessionID uuid.UUID
	FamilyID  uuid.UUID

	Audience string
	Role     string
	Scopes   []string

	AuthMethod AuthMethod

	ClientID      string
	GatewayID     string
	SourceService string
	TargetService string

	ParentTokenID uuid.UUID
	TTLSec        int64
}

// TokenRefreshRequest 表示 refresh token 刷新参数。
type TokenRefreshRequest struct {
	RefreshToken string

	ClientID  string
	GatewayID string
	SourceIP  string
	UserAgent string

	RequestID string
	TraceID   string
}

// TokenVerifyRequest 表示令牌校验参数。
type TokenVerifyRequest struct {
	RawToken string

	ExpectedTypes    []TokenType
	ExpectedAudience string
	RequireScopes    []string

	SourceService string
	TargetService string

	AllowExpiredSkewSec int64
}

// TokenRevokeRequest 表示令牌撤销参数。
type TokenRevokeRequest struct {
	TokenID   uuid.UUID
	FamilyID  uuid.UUID
	SessionID uuid.UUID

	Reason    string
	RevokedBy string

	RequestID string
	TraceID   string
}

// SessionIssueRequest 表示创建会话参数。
type SessionIssueRequest struct {
	Principal Principal
	Role      string
	Scopes    []string

	AuthMethod AuthMethod

	ClientID  string
	GatewayID string
	SourceIP  string
	UserAgent string

	ExpiresAt time.Time
}

// SessionValidateRequest 表示会话校验参数。
type SessionValidateRequest struct {
	SessionID     uuid.UUID
	PrincipalID   string
	RequireActive bool
	MinVersion    int64
}

// SessionRevokeRequest 表示会话撤销参数。
type SessionRevokeRequest struct {
	SessionID   uuid.UUID
	PrincipalID string

	Reason    string
	RevokedBy string

	RequestID string
	TraceID   string
}

// DownstreamGrantRequest 表示网关申请下游服务授权参数。
type DownstreamGrantRequest struct {
	Identity IdentityContext

	TargetService string
	BindingType   commsec.ChannelBindingType

	RequireEncryption bool
	TTLSec            int64
}
