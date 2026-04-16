package system

import (
	"strings"

	authmodel "certification_server/src/models/auth"
	commonmodel "certification_server/src/models/common"
)

// AuthControlConfig 定义认证中心等非网关模块的本地限流配置。
// 该配置不承担远程认证职责，仅用于本地资源级限流与入站控制。
type AuthControlConfig struct {
	Enabled bool

	RuleID    string
	Scope     authmodel.RateLimitScope
	Subject   authmodel.RateLimitSubjectType
	Algorithm authmodel.RateLimitAlgorithm

	Limit     int64
	Burst     int64
	WindowSec int64

	RequireAuthenticated bool

	MatchModule         string
	MatchAction         string
	MatchRoute          string
	MatchMethods        []string
	MatchEntityTypes    []commonmodel.EntityType
	MatchTokenTypes     []authmodel.TokenType
	MatchGatewayIDs     []string
	MatchSourceServices []string
	MatchTargetServices []string
	MatchScopes         []string
	MatchTags           map[string]string
}

// Normalized 返回包含默认值的本地限流配置快照。
func (c *AuthControlConfig) Normalized(defaultModule string) AuthControlConfig {
	normalized := AuthControlConfig{
		Enabled:      true,
		RuleID:       "local-auth-control",
		Scope:        authmodel.RateLimitScopeAuth,
		Subject:      authmodel.SubjectComposite,
		Algorithm:    authmodel.RateLimitFixedWindow,
		Limit:        600,
		Burst:        0,
		WindowSec:    60,
		MatchMethods: []string{"POST"},
		MatchTags:    map[string]string{},
	}

	if c != nil {
		normalized.Enabled = c.Enabled
		normalized.RuleID = strings.TrimSpace(c.RuleID)
		normalized.Scope = normalizeRateLimitScope(string(c.Scope))
		normalized.Subject = normalizeRateLimitSubjectType(string(c.Subject))
		normalized.Algorithm = normalizeRateLimitAlgorithm(string(c.Algorithm))
		normalized.Limit = c.Limit
		normalized.Burst = c.Burst
		normalized.WindowSec = c.WindowSec
		normalized.RequireAuthenticated = c.RequireAuthenticated
		normalized.MatchModule = strings.TrimSpace(c.MatchModule)
		normalized.MatchAction = strings.TrimSpace(c.MatchAction)
		normalized.MatchRoute = strings.TrimSpace(c.MatchRoute)
		normalized.MatchMethods = normalizeStringSlice(c.MatchMethods)
		normalized.MatchEntityTypes = normalizeEntityTypeSlice(c.MatchEntityTypes)
		normalized.MatchTokenTypes = normalizeTokenTypeSlice(c.MatchTokenTypes)
		normalized.MatchGatewayIDs = normalizeStringSlice(c.MatchGatewayIDs)
		normalized.MatchSourceServices = normalizeStringSlice(c.MatchSourceServices)
		normalized.MatchTargetServices = normalizeStringSlice(c.MatchTargetServices)
		normalized.MatchScopes = normalizeStringSlice(c.MatchScopes)
		normalized.MatchTags = normalizeStringMap(c.MatchTags)
	}

	if normalized.RuleID == "" {
		normalized.RuleID = "local-auth-control"
	}
	if normalized.MatchModule == "" {
		normalized.MatchModule = strings.TrimSpace(defaultModule)
	}
	if normalized.Limit <= 0 {
		normalized.Limit = 600
	}
	if normalized.Burst < 0 {
		normalized.Burst = 0
	}
	if normalized.WindowSec <= 0 {
		normalized.WindowSec = 60
	}
	if len(normalized.MatchMethods) == 0 {
		normalized.MatchMethods = []string{"POST"}
	}
	if normalized.MatchTags == nil {
		normalized.MatchTags = map[string]string{}
	}
	return normalized
}

func normalizeRateLimitScope(raw string) authmodel.RateLimitScope {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", string(authmodel.RateLimitScopeAuth):
		return authmodel.RateLimitScopeAuth
	case string(authmodel.RateLimitScopeEdgeInbound):
		return authmodel.RateLimitScopeEdgeInbound
	case string(authmodel.RateLimitScopeInternalRPC):
		return authmodel.RateLimitScopeInternalRPC
	default:
		return authmodel.RateLimitScopeAuth
	}
}

func normalizeRateLimitSubjectType(raw string) authmodel.RateLimitSubjectType {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", string(authmodel.SubjectComposite):
		return authmodel.SubjectComposite
	case string(authmodel.SubjectIP):
		return authmodel.SubjectIP
	case string(authmodel.SubjectEntity):
		return authmodel.SubjectEntity
	case string(authmodel.SubjectSession):
		return authmodel.SubjectSession
	case string(authmodel.SubjectToken):
		return authmodel.SubjectToken
	case string(authmodel.SubjectClient):
		return authmodel.SubjectClient
	case string(authmodel.SubjectGateway):
		return authmodel.SubjectGateway
	case string(authmodel.SubjectRoute):
		return authmodel.SubjectRoute
	default:
		return authmodel.SubjectComposite
	}
}

func normalizeRateLimitAlgorithm(raw string) authmodel.RateLimitAlgorithm {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", string(authmodel.RateLimitFixedWindow):
		return authmodel.RateLimitFixedWindow
	case string(authmodel.RateLimitSlidingWindow):
		return authmodel.RateLimitSlidingWindow
	case string(authmodel.RateLimitTokenBucket):
		return authmodel.RateLimitTokenBucket
	default:
		return authmodel.RateLimitFixedWindow
	}
}

func normalizeStringSlice(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeEntityTypeSlice(items []commonmodel.EntityType) []commonmodel.EntityType {
	if len(items) == 0 {
		return nil
	}
	out := make([]commonmodel.EntityType, 0, len(items))
	for _, item := range items {
		trimmed := commonmodel.EntityType(strings.ToLower(strings.TrimSpace(string(item))))
		switch trimmed {
		case commonmodel.EntityUser, commonmodel.EntityDevice, commonmodel.EntityService:
			out = append(out, trimmed)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeTokenTypeSlice(items []authmodel.TokenType) []authmodel.TokenType {
	if len(items) == 0 {
		return nil
	}
	out := make([]authmodel.TokenType, 0, len(items))
	for _, item := range items {
		trimmed := authmodel.TokenType(strings.ToLower(strings.TrimSpace(string(item))))
		switch trimmed {
		case authmodel.TokenAccess, authmodel.TokenRefresh, authmodel.TokenService, authmodel.TokenDownstream:
			out = append(out, trimmed)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		trimmedKey := strings.TrimSpace(key)
		trimmedValue := strings.TrimSpace(value)
		if trimmedKey == "" || trimmedValue == "" {
			continue
		}
		out[trimmedKey] = trimmedValue
	}
	if len(out) == 0 {
		return map[string]string{}
	}
	return out
}
