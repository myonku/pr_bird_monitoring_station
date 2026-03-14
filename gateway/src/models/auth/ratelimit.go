package auth

import "time"

type RateLimitSubjectType string // 限流主体类型，表示计数器的维度，可以是IP、实体、会话、令牌、客户端、网关、路由或复合等。
type RateLimitScope string       // 限流范围，表示规则适用的场景，可以是边缘入站、内部RPC、认证等。
type RateLimitAlgorithm string   // 限流算法，表示使用的限流算法，可以是固定窗口、滑动窗口或令牌桶等。

const (
	SubjectIP        RateLimitSubjectType = "ip"
	SubjectEntity    RateLimitSubjectType = "entity"
	SubjectSession   RateLimitSubjectType = "session"
	SubjectToken     RateLimitSubjectType = "token"
	SubjectClient    RateLimitSubjectType = "client"
	SubjectGateway   RateLimitSubjectType = "gateway"
	SubjectRoute     RateLimitSubjectType = "route"
	SubjectComposite RateLimitSubjectType = "composite"
)

const (
	RateLimitScopeEdgeInbound RateLimitScope = "edge_inbound"
	RateLimitScopeInternalRPC RateLimitScope = "internal_grpc"
	RateLimitScopeAuth        RateLimitScope = "auth"
)

const (
	RateLimitFixedWindow   RateLimitAlgorithm = "fixed_window"
	RateLimitSlidingWindow RateLimitAlgorithm = "sliding_window"
	RateLimitTokenBucket   RateLimitAlgorithm = "token_bucket"
)

// RateLimitDescriptor 代表一个限流请求的描述信息，包含模块、动作、路由、方法、来源IP、实体信息等字段。
type RateLimitDescriptor struct {
	Scope     RateLimitScope
	Transport string

	Module string
	Action string
	Route  string
	Method string

	Authenticated bool

	SourceIP  string
	GatewayID string
	ClientID  string

	SourceService string
	TargetService string

	EntityType  EntityType
	EntityID    string
	PrincipalID string
	SessionID   string
	TokenID     string
	TokenType   TokenType

	Scopes []string

	Tags map[string]string
}

// SubjectValue 返回某个限流主体对应的唯一值，供构造计数 key 使用。
func (d RateLimitDescriptor) SubjectValue(subjectType RateLimitSubjectType) string {
	switch subjectType {
	case SubjectIP:
		return d.SourceIP
	case SubjectEntity:
		if d.PrincipalID != "" {
			return d.PrincipalID
		}
		return d.EntityID
	case SubjectSession:
		return d.SessionID
	case SubjectToken:
		return d.TokenID
	case SubjectClient:
		return d.ClientID
	case SubjectGateway:
		return d.GatewayID
	case SubjectRoute:
		return d.Route
	default:
		return ""
	}
}

// RateLimitRule 描述一个可应用于网关或认证中心的限流规则。
type RateLimitRule struct {
	ID        string
	Scope     RateLimitScope
	Subject   RateLimitSubjectType
	Algorithm RateLimitAlgorithm
	Priority  int
	Enabled   bool

	Limit     int64
	Burst     int64
	WindowSec int64

	RequireAuthenticated bool

	MatchModule         string
	MatchAction         string
	MatchRoute          string
	MatchMethods        []string
	MatchEntityTypes    []EntityType
	MatchTokenTypes     []TokenType
	MatchScopes         []string
	MatchGatewayIDs     []string
	MatchSourceServices []string
	MatchTargetServices []string
	MatchTags           map[string]string
}

// RateLimitBucketKey 是分布式限流计数器使用的标准键。
type RateLimitBucketKey struct {
	RuleID       string
	Scope        RateLimitScope
	SubjectType  RateLimitSubjectType
	SubjectValue string
	Module       string
	Action       string
}

// RateLimitCounter 是一个窗口内的限流计数快照。
type RateLimitCounter struct {
	Key RateLimitBucketKey

	Hits      int64
	Remaining int64

	WindowStartedAt time.Time
	WindowResetAt   time.Time
	LastSeenAt      time.Time
	ExpiresAt       time.Time
}

// RateLimitDecision 代表限流决策的结果，包含是否允许请求、违反的规则ID、重试时间等信息。
type RateLimitDecision struct {
	Allowed        bool
	ViolatedRuleID string
	RetryAfterSec  int64
	Remaining      int64
	SubjectKey     string
	Reason         string
}
