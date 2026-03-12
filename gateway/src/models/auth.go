package models

import (
	"time"

	"github.com/google/uuid"
)

type EntityType string
type SessionStatus string
type TokenType string
type TokenStatus string
type TokenStorage string
type AuthMethod string
type ChannelBindingType string

const (
	TokenAccess     TokenType = "access"
	TokenRefresh    TokenType = "refresh"
	TokenService    TokenType = "service"
	TokenDownstream TokenType = "downstream"
)

const (
	TokenStatusActive  TokenStatus = "active"
	TokenStatusRotated TokenStatus = "rotated"
	TokenStatusRevoked TokenStatus = "revoked"
	TokenStatusExpired TokenStatus = "expired"
)

const (
	TokenStorageCache    TokenStorage = "cache"
	TokenStorageDatabase TokenStorage = "database"
	TokenStorageHybrid   TokenStorage = "hybrid"
)

const (
	AuthMethodPassword      AuthMethod = "password"
	AuthMethodDeviceSecret  AuthMethod = "device_secret"
	AuthMethodServiceSecret AuthMethod = "service_secret"
	AuthMethodRefreshToken  AuthMethod = "refresh_token"
	AuthMethodTokenExchange AuthMethod = "token_exchange"
)

const (
	ChannelBindingToken   ChannelBindingType = "token"
	ChannelBindingSession ChannelBindingType = "session"
)

const (
	SessionActive  SessionStatus = "active"
	SessionRevoked SessionStatus = "revoked"
	SessionExpired SessionStatus = "expired"
	SessionBlocked SessionStatus = "blocked"
)

const (
	EntityUser    EntityType = "user"
	EntityDevice  EntityType = "device"
	EntityService EntityType = "service"
)

// Principal 代表认证实体的主标识符，包含了实体类型和实体ID等信息。
type Principal struct {
	EntityType EntityType
	EntityID   string
}

func (p Principal) PrincipalID() string {
	if p.EntityType == "" || p.EntityID == "" {
		return ""
	}

	return string(p.EntityType) + ":" + p.EntityID
}

// IdentityContext 代表认证上下文信息，包含了认证实体的类型、ID、权限等信息。
type IdentityContext struct {
	Principal   Principal  // 认证实体的标准主标识
	EntityType  EntityType // 认证实体的类型：user/device/service
	EntityID    string     // 认证实体的ID
	PrincipalID string     // 认证实体的主标识符

	SessionID     uuid.UUID // 会话ID
	TokenID       uuid.UUID // 令牌ID（jti）
	TokenFamilyID uuid.UUID // 令牌族ID，用于 refresh 轮换和撤销联动
	TokenType     TokenType // 当前认证上下文来自哪一种令牌

	Role   string   // 用户角色
	Scopes []string // 权限范围

	AuthMethod AuthMethod // 认证方法：password/device_secret/service_secret/refresh_token/token_exchange
	SourceIP   string     // 认证请求的来源IP地址
	ClientID   string     // 认证请求的客户端ID（如果有的话）
	GatewayID  string     // 当前入口网关标识

	SourceService string // 发起当前调用的服务名称
	TargetService string // 当前请求目标服务名称

	UserAgent string // 认证请求的User-Agent信息
	RequestID string // 认证请求的唯一标识符（如果有的话）
	TraceID   string // 认证请求的Trace ID（如果有的话）

	SecureChannelID     uuid.UUID           // 当前请求绑定的应用层加密通道ID
	SecureChannelStatus SecureChannelStatus // 当前加密通道状态
	CipherSuite         CipherSuite         // 当前请求使用的对称加密套件

	IssuedAt  time.Time // 认证上下文的签发时间
	ExpiresAt time.Time // 认证上下文的过期时间
}

// Session 代表认证服务器中的会话实体，包含了会话的基本信息、状态、权限快照等内容。
type Session struct {
	ID          uuid.UUID  // 会话ID
	Principal   Principal  // 认证实体的标准主标识
	EntityType  EntityType // 认证实体的类型：user/device/service
	EntityID    string     // 认证实体的ID
	PrincipalID string     // 认证实体的主标识符（type:id）

	Status     SessionStatus // 会话状态：active/revoked/expired/blocked
	AuthMethod AuthMethod    // 创建该会话时使用的认证方式

	CreatedByIP string // 会话创建时的IP地址
	LastSeenIP  string // 会话最后一次被使用时的IP地址
	UserAgent   string // 会话最后一次被使用时的User-Agent信息
	ClientID    string // 会话最后一次被使用时的客户端ID（如果有的话）
	GatewayID   string // 会话当前绑定或最近经过的网关标识

	ScopeSnapshot []string  // 会话创建时的权限范围快照
	RoleSnapshot  string    // 会话创建时的用户角色快照（仅用户适用）
	TokenFamilyID uuid.UUID // 当前活跃 refresh 令牌族ID

	CreatedAt      time.Time // 会话创建时间
	UpdatedAt      time.Time // 会话更新时间
	LastSeenAt     time.Time // 会话最后一次被使用的时间
	LastVerifiedAt time.Time // 最近一次完成 refresh/状态校验的时间
	NextRefreshAt  time.Time // 下次需要执行 refresh 或重校验的时间
	ExpiresAt      time.Time // 会话过期时间
	RevokedAt      time.Time // 会话撤销时间
	Version        int64     // 会话版本号，用于实现分布式环境下的会话一致性控制
}

// TokenFamily 用于跟踪长短期令牌的轮换关系。
// 一般 refresh 令牌落库保存，access/downstream 令牌落缓存保存。
type TokenFamily struct {
	ID uuid.UUID

	SessionID    uuid.UUID
	Principal    Principal
	PrincipalID  string
	CurrentToken uuid.UUID // 当前有效的长期令牌ID，通常指 refresh token

	Status  TokenStatus
	Storage TokenStorage

	LastIssuedAccessID uuid.UUID // 最近一次颁发的 access/downstream 令牌ID

	CreatedAt       time.Time
	LastValidatedAt time.Time
	NextRefreshAt   time.Time
	ExpiresAt       time.Time
	RevokedAt       time.Time
	Version         int64
}

// TokenClaims 代表认证服务器中生成的访问令牌的声明信息，包含了令牌的基本信息、权限信息等内容。
type TokenClaims struct {
	Issuer   string    // 认证服务器的标识
	Audience string    // 令牌的受众，可以是用户、设备或服务等
	Subject  string    // 令牌的主题，通常是认证实体的ID
	Type     TokenType // 令牌类型：access/refresh/service/downstream

	EntityType  EntityType // 认证实体的类型：user/device/service
	EntityID    string     // 认证实体的ID
	PrincipalID string     // 认证实体主标识符
	SessionID   uuid.UUID  // 令牌所属的会话ID
	TokenID     uuid.UUID  // 令牌的唯一标识符（jti）
	FamilyID    uuid.UUID  // 所属令牌族ID
	ParentID    uuid.UUID  // 上游令牌ID，供 token exchange 或 refresh 链追踪使用

	Role       string     // 认证实体的角色（仅用户适用）
	Scopes     []string   // 认证实体的权限范围
	AuthMethod AuthMethod // 认证方法：password/device_secret/service_secret/refresh_token/token_exchange

	ClientID      string // 当前令牌绑定的客户端ID
	GatewayID     string // 当前令牌绑定的网关ID
	SourceService string // 令牌代表的上游服务
	TargetService string // 令牌允许访问的目标服务

	IssuedAt  time.Time // 令牌的签发时间
	ExpiresAt time.Time // 令牌的过期时间
}

// TokenRecord 表示令牌元数据在缓存或数据库中的落库记录。
type TokenRecord struct {
	ID        uuid.UUID
	FamilyID  uuid.UUID
	SessionID uuid.UUID

	Type    TokenType
	Status  TokenStatus
	Storage TokenStorage

	Principal   Principal
	PrincipalID string

	ParentTokenID uuid.UUID
	ClientID      string
	GatewayID     string

	RoleSnapshot  string
	ScopeSnapshot []string

	IssuedAt        time.Time
	ExpiresAt       time.Time
	LastValidatedAt time.Time
	RevokedAt       time.Time
}

// IssuedToken 是令牌签发后的统一返回结构。
type IssuedToken struct {
	Raw     string
	Type    TokenType
	Storage TokenStorage
	Claims  TokenClaims
	TTLSec  int64
}

// TokenBundle 表示一次认证或刷新后返回的一组令牌。
type TokenBundle struct {
	AccessToken     *IssuedToken
	RefreshToken    *IssuedToken
	DownstreamToken *IssuedToken
}

// TokenVerificationResult 表示网关或内部服务对令牌执行验证后的结果。
type TokenVerificationResult struct {
	Valid                bool
	Status               TokenStatus
	Identity             *IdentityContext
	Token                *TokenRecord
	RevalidationRequired bool
	FailureReason        string
}

// DownstreamAccessGrant 描述网关向内部服务转发的 gRPC 访问授权上下文。
type DownstreamAccessGrant struct {
	GatewayID     string
	SourceService string
	TargetService string

	SessionID   uuid.UUID
	TokenID     uuid.UUID
	PrincipalID string
	BindingType ChannelBindingType

	Scopes []string

	EncryptionRequired bool
	SecureChannelID    uuid.UUID
	CipherSuite        CipherSuite

	IssuedAt  time.Time
	ExpiresAt time.Time
}

// SessionTouchMeta 包含了更新会话信息时需要的上下文信息，这些信息可以帮助认证服务进行安全审计和异常检测。
type SessionTouchMeta struct {
	SourceIP  string
	UserAgent string
	TraceID   string
	RequestID string
	ClientID  string
	GatewayID string
	Route     string
	Method    string
}
