package authcontrolsvc

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	authmodel "gateway/src/models/auth"
	modelsystem "gateway/src/models/system"
)

const (
	defaultRateLimitWindowSec = int64(60)
	defaultRateLimitLimit     = int64(600)
	defaultRateLimitRuleID    = "gateway-authcontrol-default"
)

// LocalRateLimiterService 提供 gateway 默认的进程内限流能力。
type LocalRateLimiterService struct {
	mu           sync.Mutex
	now          func() time.Time
	windowSec    int64
	limit        int64
	fixedWindows map[string]*fixedWindowState
}

type fixedWindowState struct {
	WindowStartedAt time.Time
	WindowResetAt   time.Time
	Hits            int64
}

// NewLocalRateLimiterService 构造 gateway 本地限流器。
func NewLocalRateLimiterService() *LocalRateLimiterService {
	return &LocalRateLimiterService{
		now:          time.Now,
		windowSec:    defaultRateLimitWindowSec,
		limit:        defaultRateLimitLimit,
		fixedWindows: map[string]*fixedWindowState{},
	}
}

// Decide 基于描述符执行固定窗口限流。
func (s *LocalRateLimiterService) Decide(
	ctx context.Context,
	descriptor *authmodel.RateLimitDescriptor,
) (*authmodel.RateLimitDecision, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if descriptor == nil {
		return nil, &modelsystem.ErrRateLimitRequestInvalid
	}

	now := s.now().UTC()
	windowSec := s.windowSec
	if windowSec <= 0 {
		windowSec = defaultRateLimitWindowSec
	}
	window := time.Duration(windowSec) * time.Second
	if window <= 0 {
		window = time.Duration(defaultRateLimitWindowSec) * time.Second
	}

	limit := s.limit
	if limit <= 0 {
		limit = defaultRateLimitLimit
	}

	subjectKey := buildRateLimitSubjectKey(descriptor)
	bucketKey := buildRateLimitBucketKey(descriptor, subjectKey)

	s.mu.Lock()
	state := s.fixedWindows[bucketKey]
	if state == nil || !now.Before(state.WindowResetAt) {
		state = &fixedWindowState{
			WindowStartedAt: now,
			WindowResetAt:   now.Add(window),
			Hits:            0,
		}
		s.fixedWindows[bucketKey] = state
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
			ViolatedRuleID: defaultRateLimitRuleID,
			RetryAfterSec:  retryAfter,
			Remaining:      0,
			SubjectKey:     subjectKey,
			Reason:         fmt.Sprintf("rate limited by %s", defaultRateLimitRuleID),
		}, nil
	}

	return &authmodel.RateLimitDecision{
		Allowed:        true,
		ViolatedRuleID: "",
		RetryAfterSec:  0,
		Remaining:      remaining,
		SubjectKey:     subjectKey,
		Reason:         "allowed",
	}, nil
}

func buildRateLimitSubjectKey(descriptor *authmodel.RateLimitDescriptor) string {
	if descriptor == nil {
		return ""
	}

	if subjectKey := strings.TrimSpace(descriptor.SubjectValue(authmodel.SubjectComposite)); subjectKey != "" {
		return subjectKey
	}
	if principalID := strings.TrimSpace(descriptor.PrincipalID); principalID != "" {
		return principalID
	}
	if clientID := strings.TrimSpace(descriptor.ClientID); clientID != "" {
		return clientID
	}
	if sourceIP := strings.TrimSpace(descriptor.SourceIP); sourceIP != "" {
		return sourceIP
	}
	if route := strings.TrimSpace(descriptor.Route); route != "" {
		return route
	}
	return "anonymous"
}

func buildRateLimitBucketKey(descriptor *authmodel.RateLimitDescriptor, subjectKey string) string {
	if descriptor == nil {
		return subjectKey
	}

	return strings.Join([]string{
		strings.TrimSpace(string(descriptor.Scope)),
		strings.TrimSpace(descriptor.Module),
		strings.TrimSpace(descriptor.Action),
		strings.TrimSpace(descriptor.Route),
		strings.TrimSpace(descriptor.Method),
		subjectKey,
	}, "|")
}
