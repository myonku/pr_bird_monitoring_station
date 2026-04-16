package authcontrolsvc

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	authcontrolif "certification_server/src/iface/authcontrol"
	authmodel "certification_server/src/models/auth"
	commonmodel "certification_server/src/models/common"
	modelsystem "certification_server/src/models/system"
)

var _ authcontrolif.IInboundAuthControl = (*InboundAuthControlService)(nil)

// InboundAuthControlService 为认证中心提供本地级入站限流能力。
// 该实现不调用其他服务，仅依赖本地配置与进程内计数器。
type InboundAuthControlService struct {
	cfg modelsystem.AuthControlConfig
	now func() time.Time

	mu           sync.Mutex
	fixedWindows map[string]*fixedWindowState
	tokenBuckets map[string]*tokenBucketState
}

type fixedWindowState struct {
	WindowStartedAt time.Time
	WindowResetAt   time.Time
	Hits            int64
}

type tokenBucketState struct {
	Tokens       float64
	LastRefillAt time.Time
	LastSeenAt   time.Time
	Capacity     float64
	RefillPerSec float64
}

// NewInboundAuthControlService 构造认证中心本地限流门面。
func NewInboundAuthControlService(cfg modelsystem.AuthControlConfig) authcontrolif.IInboundAuthControl {
	return &InboundAuthControlService{
		cfg:          cfg,
		now:          time.Now,
		fixedWindows: map[string]*fixedWindowState{},
		tokenBuckets: map[string]*tokenBucketState{},
	}
}

// EnforceInbound 将入站上下文转换为本地限流决策。
func (s *InboundAuthControlService) EnforceInbound(
	ctx context.Context,
	req *authcontrolif.InboundControlRequest,
) (*authcontrolif.InboundControlResult, error) {
	if ctx != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
	}
	if req == nil || req.RateLimitInput == nil {
		return nil, &modelsystem.ErrInboundRateLimitInputNil
	}

	descriptor, err := authcontrolif.Build(req.RateLimitInput)
	if err != nil {
		return nil, err
	}

	now := s.now().UTC()
	decision := s.decide(now, descriptor)
	return &authcontrolif.InboundControlResult{RateLimitDecision: decision}, nil
}

func (s *InboundAuthControlService) decide(now time.Time, descriptor *authmodel.RateLimitDescriptor) *authmodel.RateLimitDecision {
	if descriptor == nil {
		return &authmodel.RateLimitDecision{
			Allowed: false,
			Reason:  "rate limit descriptor is nil",
		}
	}

	if !s.cfg.Enabled {
		return &authmodel.RateLimitDecision{
			Allowed:    true,
			Remaining:  -1,
			SubjectKey: buildSubjectKey(descriptor, s.cfg.Subject),
			Reason:     "auth control disabled",
		}
	}

	rule := s.cfg
	if !ruleMatchesConfig(rule, descriptor) {
		return &authmodel.RateLimitDecision{
			Allowed:    true,
			Remaining:  -1,
			SubjectKey: buildSubjectKey(descriptor, s.cfg.Subject),
			Reason:     "no matching local auth control rule",
		}
	}

	subjectKey := buildSubjectKey(descriptor, rule.Subject)
	if subjectKey == "" {
		subjectKey = buildCompositeSubjectKey(descriptor)
	}
	if subjectKey == "" {
		subjectKey = "anonymous"
	}

	switch rule.Algorithm {
	case authmodel.RateLimitTokenBucket:
		return s.decideTokenBucket(now, rule, descriptor, subjectKey)
	case authmodel.RateLimitSlidingWindow:
		fallthrough
	case authmodel.RateLimitFixedWindow:
		fallthrough
	default:
		return s.decideFixedWindow(now, rule, descriptor, subjectKey)
	}
}

func (s *InboundAuthControlService) decideFixedWindow(
	now time.Time,
	rule modelsystem.AuthControlConfig,
	descriptor *authmodel.RateLimitDescriptor,
	subjectKey string,
) *authmodel.RateLimitDecision {
	windowSec := rule.WindowSec
	if windowSec <= 0 {
		windowSec = 60
	}
	window := time.Duration(windowSec) * time.Second
	if window <= 0 {
		window = 60 * time.Second
	}

	limit := rule.Limit
	if limit <= 0 {
		limit = 600
	}

	key := bucketKeyString(rule.RuleID, descriptor, subjectKey)

	s.mu.Lock()
	state := s.fixedWindows[key]
	if state == nil || !now.Before(state.WindowResetAt) {
		state = &fixedWindowState{
			WindowStartedAt: now,
			WindowResetAt:   now.Add(window),
			Hits:            0,
		}
		s.fixedWindows[key] = state
	}
	state.Hits++
	hits := state.Hits
	windowResetAt := state.WindowResetAt
	s.mu.Unlock()

	remaining := limit - hits
	if remaining < 0 {
		remaining = 0
	}

	if hits > limit {
		retryAfter := int64(math.Ceil(windowResetAt.Sub(now).Seconds()))
		if retryAfter < 1 {
			retryAfter = 1
		}
		return &authmodel.RateLimitDecision{
			Allowed:        false,
			ViolatedRuleID: rule.RuleID,
			RetryAfterSec:  retryAfter,
			Remaining:      0,
			SubjectKey:     subjectKey,
			Reason:         fmt.Sprintf("rate limited by local rule %s", rule.RuleID),
		}
	}

	return &authmodel.RateLimitDecision{
		Allowed:        true,
		ViolatedRuleID: "",
		RetryAfterSec:  0,
		Remaining:      remaining,
		SubjectKey:     subjectKey,
		Reason:         "allowed",
	}
}

func (s *InboundAuthControlService) decideTokenBucket(
	now time.Time,
	rule modelsystem.AuthControlConfig,
	descriptor *authmodel.RateLimitDescriptor,
	subjectKey string,
) *authmodel.RateLimitDecision {
	windowSec := rule.WindowSec
	if windowSec <= 0 {
		windowSec = 60
	}
	limit := rule.Limit
	if limit <= 0 {
		limit = 600
	}
	burst := rule.Burst
	if burst < 0 {
		burst = 0
	}

	capacity := float64(limit + burst)
	if capacity <= 0 {
		capacity = float64(limit)
	}
	if capacity <= 0 {
		capacity = 600
	}
	refillPerSec := float64(limit) / float64(windowSec)
	if refillPerSec <= 0 {
		refillPerSec = 1
	}

	key := bucketKeyString(rule.RuleID, descriptor, subjectKey)

	s.mu.Lock()
	state := s.tokenBuckets[key]
	if state == nil {
		state = &tokenBucketState{
			Tokens:       capacity,
			LastRefillAt: now,
			LastSeenAt:   now,
			Capacity:     capacity,
			RefillPerSec: refillPerSec,
		}
		s.tokenBuckets[key] = state
	}
	elapsed := now.Sub(state.LastRefillAt).Seconds()
	if elapsed > 0 {
		state.Tokens = math.Min(state.Capacity, state.Tokens+elapsed*state.RefillPerSec)
		state.LastRefillAt = now
	}
	state.LastSeenAt = now
	state.Capacity = capacity
	state.RefillPerSec = refillPerSec

	if state.Tokens >= 1 {
		state.Tokens -= 1
		remaining := int64(math.Floor(state.Tokens))
		if remaining < 0 {
			remaining = 0
		}
		s.mu.Unlock()
		return &authmodel.RateLimitDecision{
			Allowed:        true,
			ViolatedRuleID: "",
			RetryAfterSec:  0,
			Remaining:      remaining,
			SubjectKey:     subjectKey,
			Reason:         "allowed",
		}
	}

	missing := 1 - state.Tokens
	retryAfter := int64(math.Ceil(missing / state.RefillPerSec))
	if retryAfter < 1 {
		retryAfter = 1
	}
	state.Tokens = math.Max(0, state.Tokens)
	s.mu.Unlock()

	return &authmodel.RateLimitDecision{
		Allowed:        false,
		ViolatedRuleID: rule.RuleID,
		RetryAfterSec:  retryAfter,
		Remaining:      0,
		SubjectKey:     subjectKey,
		Reason:         fmt.Sprintf("rate limited by local rule %s", rule.RuleID),
	}
}

func ruleMatchesConfig(cfg modelsystem.AuthControlConfig, descriptor *authmodel.RateLimitDescriptor) bool {
	if descriptor == nil {
		return false
	}
	if descriptor.Scope != cfg.Scope {
		return false
	}
	if cfg.MatchModule != "" && !strings.EqualFold(strings.TrimSpace(descriptor.Module), cfg.MatchModule) {
		return false
	}
	if cfg.MatchAction != "" && !strings.EqualFold(strings.TrimSpace(descriptor.Action), cfg.MatchAction) {
		return false
	}
	if cfg.MatchRoute != "" && strings.TrimSpace(descriptor.Route) != cfg.MatchRoute {
		return false
	}
	if len(cfg.MatchMethods) > 0 && !stringListContainsFold(cfg.MatchMethods, descriptor.Method) {
		return false
	}
	if cfg.RequireAuthenticated && !descriptor.Authenticated {
		return false
	}
	if len(cfg.MatchEntityTypes) > 0 && !entityTypeInList(cfg.MatchEntityTypes, descriptor.EntityType) {
		return false
	}
	if len(cfg.MatchTokenTypes) > 0 && !tokenTypeInList(cfg.MatchTokenTypes, descriptor.TokenType) {
		return false
	}
	if len(cfg.MatchGatewayIDs) > 0 && !stringListContainsFold(cfg.MatchGatewayIDs, descriptor.GatewayID) {
		return false
	}
	if len(cfg.MatchSourceServices) > 0 && !stringListContainsFold(cfg.MatchSourceServices, descriptor.SourceService) {
		return false
	}
	if len(cfg.MatchTargetServices) > 0 && !stringListContainsFold(cfg.MatchTargetServices, descriptor.TargetService) {
		return false
	}
	if len(cfg.MatchScopes) > 0 && !stringListContainsAllFold(descriptor.Scopes, cfg.MatchScopes) {
		return false
	}
	if len(cfg.MatchTags) > 0 && !tagMapMatches(descriptor.Tags, cfg.MatchTags) {
		return false
	}
	return true
}

func buildSubjectKey(descriptor *authmodel.RateLimitDescriptor, subject authmodel.RateLimitSubjectType) string {
	if descriptor == nil {
		return ""
	}
	switch subject {
	case authmodel.SubjectComposite:
		return buildCompositeSubjectKey(descriptor)
	default:
		value := strings.TrimSpace(descriptor.SubjectValue(subject))
		if value != "" {
			return value
		}
		return buildCompositeSubjectKey(descriptor)
	}
}

func buildCompositeSubjectKey(descriptor *authmodel.RateLimitDescriptor) string {
	if descriptor == nil {
		return ""
	}
	parts := []string{
		"scope=" + strings.TrimSpace(string(descriptor.Scope)),
		"module=" + strings.TrimSpace(descriptor.Module),
		"action=" + strings.TrimSpace(descriptor.Action),
		"route=" + strings.TrimSpace(descriptor.Route),
		"method=" + strings.TrimSpace(descriptor.Method),
		"source_ip=" + strings.TrimSpace(descriptor.SourceIP),
		"gateway_id=" + strings.TrimSpace(descriptor.GatewayID),
		"client_id=" + strings.TrimSpace(descriptor.ClientID),
		"source_service=" + strings.TrimSpace(descriptor.SourceService),
		"target_service=" + strings.TrimSpace(descriptor.TargetService),
		"entity_type=" + strings.TrimSpace(string(descriptor.EntityType)),
		"entity_id=" + strings.TrimSpace(descriptor.EntityID),
		"principal_id=" + strings.TrimSpace(descriptor.PrincipalID),
		"session_id=" + strings.TrimSpace(descriptor.SessionID),
		"token_id=" + strings.TrimSpace(descriptor.TokenID),
	}
	filtered := make([]string, 0, len(parts))
	for _, item := range parts {
		if strings.HasSuffix(item, "=") {
			continue
		}
		filtered = append(filtered, item)
	}
	if len(filtered) == 0 {
		return ""
	}
	return strings.Join(filtered, "|")
}

func bucketKeyString(ruleID string, descriptor *authmodel.RateLimitDescriptor, subjectKey string) string {
	module := ""
	action := ""
	scope := ""
	if descriptor != nil {
		module = strings.TrimSpace(descriptor.Module)
		action = strings.TrimSpace(descriptor.Action)
		scope = strings.TrimSpace(string(descriptor.Scope))
	}
	return strings.Join([]string{
		strings.TrimSpace(ruleID),
		scope,
		module,
		action,
		strings.TrimSpace(subjectKey),
	}, "|")
}

func stringListContainsFold(items []string, value string) bool {
	needle := strings.TrimSpace(value)
	if needle == "" {
		return false
	}
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item), needle) {
			return true
		}
	}
	return false
}

func stringListContainsAllFold(haystack []string, needles []string) bool {
	if len(needles) == 0 {
		return true
	}
	for _, needle := range needles {
		if !stringListContainsFold(haystack, needle) {
			return false
		}
	}
	return true
}

func entityTypeInList(items []commonmodel.EntityType, value commonmodel.EntityType) bool {
	needle := strings.TrimSpace(strings.ToLower(string(value)))
	if needle == "" {
		return false
	}
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(string(item)), needle) {
			return true
		}
	}
	return false
}

func tokenTypeInList(items []authmodel.TokenType, value authmodel.TokenType) bool {
	needle := strings.TrimSpace(strings.ToLower(string(value)))
	if needle == "" {
		return false
	}
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(string(item)), needle) {
			return true
		}
	}
	return false
}

func tagMapMatches(actual map[string]string, expected map[string]string) bool {
	if len(expected) == 0 {
		return true
	}
	if len(actual) == 0 {
		return false
	}
	for key, expectedValue := range expected {
		actualValue, ok := actual[key]
		if !ok {
			return false
		}
		if strings.TrimSpace(actualValue) != strings.TrimSpace(expectedValue) {
			return false
		}
	}
	return true
}
