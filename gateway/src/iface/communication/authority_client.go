package communication

import (
	"time"

	authmodel "gateway/src/models/auth"
)

// UserPasswordAuthRequest 定义用户名密码认证请求。
type UserPasswordAuthRequest struct {
	Username string
	Password string

	Audience string
	Scopes   []string

	ClientID  string
	GatewayID string
	SourceIP  string
	UserAgent string

	RequestID string
	TraceID   string
}

// UserPasswordAuthResult 定义用户名密码认证结果。
type UserPasswordAuthResult struct {
	Identity *authmodel.IdentityContext
	Session  *authmodel.Session
	Tokens   authmodel.TokenBundle

	IssuedAt  time.Time
	ExpiresAt time.Time
}
