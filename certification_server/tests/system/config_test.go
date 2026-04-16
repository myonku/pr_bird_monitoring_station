package system_test

import (
	"testing"

	authmodel "certification_server/src/models/auth"
	system "certification_server/src/models/system"
)

func TestBuildSecretKeyStartupParams(t *testing.T) {
	t.Run("falls back to instance id", func(t *testing.T) {
		cfg := &system.ProjectConfig{
			Runtime: &system.RuntimeConfig{
				ServiceName: "certification_server",
				InstanceID:  "instance-123",
				RunMode:     system.RuntimeRunModeDevelopment,
			},
			Auth: &system.AuthConfig{
				SecretKeyDir: "  secret_keys  ",
			},
		}

		params := cfg.BuildSecretKeyStartupParams("fallback-instance")
		if params.ActiveKeyID != "instance-123" {
			t.Fatalf("expected active key id to fall back to instance id, got %q", params.ActiveKeyID)
		}
		if params.InstanceID != "instance-123" {
			t.Fatalf("expected instance id to be preserved, got %q", params.InstanceID)
		}
		if params.SecretKeyDir != "secret_keys" {
			t.Fatalf("expected secret key dir to be trimmed, got %q", params.SecretKeyDir)
		}
	})

	t.Run("prefers active key id", func(t *testing.T) {
		cfg := &system.ProjectConfig{
			Runtime: &system.RuntimeConfig{
				ServiceName: "certification_server",
				InstanceID:  "instance-123",
				RunMode:     system.RuntimeRunModeDevelopment,
			},
			Auth: &system.AuthConfig{
				SecretKeyDir: "secret_keys",
				ActiveKeyID:  "active-key-456",
			},
		}

		params := cfg.BuildSecretKeyStartupParams("fallback-instance")
		if params.ActiveKeyID != "active-key-456" {
			t.Fatalf("expected active key id to win, got %q", params.ActiveKeyID)
		}
	})
}

func TestAuthControlConfigNormalized(t *testing.T) {
	cfg := &system.AuthControlConfig{
		Enabled:     false,
		RuleID:      "  ",
		Scope:       authmodel.RateLimitScopeAuth,
		Subject:     authmodel.SubjectComposite,
		Algorithm:   authmodel.RateLimitTokenBucket,
		Limit:       0,
		Burst:       -1,
		WindowSec:   0,
		MatchModule: "",
	}

	normalized := cfg.Normalized("certification_server")
	if normalized.Enabled {
		t.Fatalf("expected enabled flag to preserve false value")
	}
	if normalized.RuleID != "local-auth-control" {
		t.Fatalf("expected default rule id, got %q", normalized.RuleID)
	}
	if normalized.MatchModule != "certification_server" {
		t.Fatalf("expected module fallback, got %q", normalized.MatchModule)
	}
	if normalized.Limit != 600 {
		t.Fatalf("expected limit default 600, got %d", normalized.Limit)
	}
	if normalized.Burst != 0 {
		t.Fatalf("expected burst default 0, got %d", normalized.Burst)
	}
	if normalized.WindowSec != 60 {
		t.Fatalf("expected window default 60, got %d", normalized.WindowSec)
	}
	if len(normalized.MatchMethods) != 1 || normalized.MatchMethods[0] != "POST" {
		t.Fatalf("expected default POST match method, got %#v", normalized.MatchMethods)
	}
	if normalized.Algorithm != authmodel.RateLimitTokenBucket {
		t.Fatalf("expected algorithm to remain token bucket, got %s", normalized.Algorithm)
	}
	if normalized.MatchTags == nil {
		t.Fatalf("expected match tags map to be initialized")
	}
}
