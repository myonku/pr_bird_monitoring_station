package auth

import (
	"time"

	commsec "gateway/src/models/commsec"

	"github.com/google/uuid"
)

type BootstrapStage string

const (
	BootstrapStageUninitialized  BootstrapStage = "uninitialized"
	BootstrapStageChallenging    BootstrapStage = "challenging"
	BootstrapStageAuthenticating BootstrapStage = "authenticating"
	BootstrapStageReady          BootstrapStage = "ready"
)

// ChallengeRequest 表示实体请求认证中心签发一次性挑战的参数。
type ChallengeRequest struct {
	EntityType EntityType
	EntityID   string
	KeyID      string

	Audience string

	ClientID  string
	GatewayID string
	SourceIP  string
	UserAgent string

	RequestID string
	TraceID   string

	TTLSec int64
}

// ChallengePayload 是认证中心签发给实体用于签名证明的挑战内容。
type ChallengePayload struct {
	ChallengeID uuid.UUID

	Issuer   string
	Audience string

	EntityType EntityType
	EntityID   string
	KeyID      string

	Nonce string

	IssuedAt  time.Time
	ExpiresAt time.Time
}

// SignedChallengeResponse 是实体对 ChallengePayload 签名后的回包。
type SignedChallengeResponse struct {
	ChallengeID uuid.UUID
	KeyID       string

	SignatureAlgorithm commsec.SignatureAlgorithm
	Signature          string

	SignedAt time.Time
}

// BootstrapAuthRequest 表示实体在冷启动阶段提交认证请求的载体。
type BootstrapAuthRequest struct {
	Challenge ChallengePayload
	Signed    SignedChallengeResponse

	Scopes []string
	Role   string

	RequireDownstreamToken bool
}

// BootstrapAuthResult 表示冷启动认证完成后的返回结果。
type BootstrapAuthResult struct {
	Stage BootstrapStage

	Identity *IdentityContext
	Session  *Session
	Tokens   TokenBundle

	ActiveCommKeyID string

	IssuedAt  time.Time
	ExpiresAt time.Time
}
