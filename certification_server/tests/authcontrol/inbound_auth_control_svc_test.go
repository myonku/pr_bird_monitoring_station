package authcontrol_test

import (
	"context"
	"testing"

	authcontroliface "certification_server/src/iface/authcontrol"
	authmodel "certification_server/src/models/auth"
	system "certification_server/src/models/system"
	authcontrolsvc "certification_server/src/services/authcontrol"
)

func TestInboundAuthControlServiceDecisions(t *testing.T) {
	baseRequest := &authcontroliface.InboundControlRequest{
		RateLimitInput: &authcontroliface.InboundRateLimitInput{
			Scope:         authmodel.RateLimitScopeAuth,
			Transport:     "grpc",
			Module:        "certification_server",
			Action:        "bootstrap",
			Route:         "bootstrap.challenge",
			Method:        "POST",
			SourceIP:      "127.0.0.1",
			GatewayID:     "gateway-1",
			ClientID:      "client-1",
			SourceService: "gateway",
			TargetService: "certification_server",
			Tags:          map[string]string{"env": "test"},
		},
	}

	t.Run("allow then deny within fixed window", func(t *testing.T) {
		svc := authcontrolsvc.NewInboundAuthControlService(system.AuthControlConfig{
			Enabled:      true,
			RuleID:       "local-auth-control",
			Scope:        authmodel.RateLimitScopeAuth,
			Subject:      authmodel.SubjectComposite,
			Algorithm:    authmodel.RateLimitFixedWindow,
			Limit:        1,
			Burst:        0,
			WindowSec:    60,
			MatchModule:  "certification_server",
			MatchAction:  "bootstrap",
			MatchMethods: []string{"POST"},
		})

		first, err := svc.EnforceInbound(context.Background(), baseRequest)
		if err != nil {
			t.Fatalf("unexpected error on first request: %v", err)
		}
		if first == nil || first.RateLimitDecision == nil {
			t.Fatalf("expected rate limit decision on first request")
		}
		if !first.RateLimitDecision.Allowed {
			t.Fatalf("expected first request to be allowed")
		}
		if first.RateLimitDecision.Remaining != 0 {
			t.Fatalf("expected no remaining quota after first request, got %d", first.RateLimitDecision.Remaining)
		}

		second, err := svc.EnforceInbound(context.Background(), baseRequest)
		if err != nil {
			t.Fatalf("unexpected error on second request: %v", err)
		}
		if second == nil || second.RateLimitDecision == nil {
			t.Fatalf("expected rate limit decision on second request")
		}
		if second.RateLimitDecision.Allowed {
			t.Fatalf("expected second request to be denied")
		}
		if second.RateLimitDecision.ViolatedRuleID != "local-auth-control" {
			t.Fatalf("expected violated rule id to be preserved, got %q", second.RateLimitDecision.ViolatedRuleID)
		}
		if second.RateLimitDecision.RetryAfterSec <= 0 {
			t.Fatalf("expected positive retry-after value, got %d", second.RateLimitDecision.RetryAfterSec)
		}
	})

	t.Run("disabled rule allows request", func(t *testing.T) {
		svc := authcontrolsvc.NewInboundAuthControlService(system.AuthControlConfig{
			Enabled:     false,
			RuleID:      "local-auth-control",
			Scope:       authmodel.RateLimitScopeAuth,
			Subject:     authmodel.SubjectComposite,
			Algorithm:   authmodel.RateLimitFixedWindow,
			Limit:       1,
			WindowSec:   60,
			MatchModule: "certification_server",
		})

		result, err := svc.EnforceInbound(context.Background(), baseRequest)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil || result.RateLimitDecision == nil {
			t.Fatalf("expected decision for disabled config")
		}
		if !result.RateLimitDecision.Allowed {
			t.Fatalf("expected disabled config to allow request")
		}
		if result.RateLimitDecision.Reason != "auth control disabled" {
			t.Fatalf("expected disabled reason, got %q", result.RateLimitDecision.Reason)
		}
	})

	t.Run("unmatched rule bypasses local limiter", func(t *testing.T) {
		svc := authcontrolsvc.NewInboundAuthControlService(system.AuthControlConfig{
			Enabled:     true,
			RuleID:      "local-auth-control",
			Scope:       authmodel.RateLimitScopeAuth,
			Subject:     authmodel.SubjectComposite,
			Algorithm:   authmodel.RateLimitFixedWindow,
			Limit:       1,
			WindowSec:   60,
			MatchModule: "other_service",
		})

		result, err := svc.EnforceInbound(context.Background(), baseRequest)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil || result.RateLimitDecision == nil {
			t.Fatalf("expected decision for unmatched config")
		}
		if !result.RateLimitDecision.Allowed {
			t.Fatalf("expected unmatched rule to bypass limiter")
		}
		if result.RateLimitDecision.Reason != "no matching local auth control rule" {
			t.Fatalf("expected bypass reason, got %q", result.RateLimitDecision.Reason)
		}
	})
}
