package system_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	authmodel "certification_server/src/models/auth"
	system "certification_server/src/models/system"
)

func TestLoadConfigParsesAuthControlSection(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "settings.toml")

	content := `
[runtime]
service_name = "certification_server"
instance_id = "cert-instance"
run_mode = "no_auth"

[mysql]
dsn = "certification:certification@tcp(127.0.0.1:3306)/pr_bird_monitoring_station?charset=utf8mb4&parseTime=true&loc=Local"
dsns = "certification:certification@tcp(127.0.0.1:3306)/pr_bird_monitoring_station?charset=utf8mb4&parseTime=true&loc=Local, certification:certification@tcp(127.0.0.1:3307)/pr_bird_monitoring_station?charset=utf8mb4&parseTime=true&loc=Local"
max_open_conns = 8
max_idle_conns = 4
conn_max_lifetime = "30m"
conn_max_idle_time = "10m"
op_timeout = "3s"
circuit_breaker_failure_threshold = 5
circuit_breaker_recovery_timeout = "10s"
circuit_breaker_half_open_max_calls = 1

[redis]
mode = "standalone"
addr = "127.0.0.1:6379"
db = 0
max_retries = 3
pool_size = 10
min_idle_conns = 2
dial_timeout = "2s"
read_timeout = "2s"
write_timeout = "2s"
read_only = false
route_by_latency = true
route_randomly = false
op_timeout = "3s"
default_ttl = "24h"
circuit_breaker_failure_threshold = 5
circuit_breaker_recovery_timeout = "10s"
circuit_breaker_half_open_max_calls = 1

[etcd]
endpoints = "127.0.0.1:2379,127.0.0.1:2380"
username = "etcd-user"
password = "etcd-pass"
dial_timeout = "5s"
auto_sync_interval = "30s"
op_timeout = "3s"
circuit_breaker_failure_threshold = 6
circuit_breaker_recovery_timeout = "25s"
circuit_breaker_half_open_max_calls = 2

[auth]
secret_key_dir = "secret_keys"
active_key_id = "cert-local-key"

[auth_control]
enabled = true
rule_id = "local-auth-control"
scope = "auth"
subject = "composite"
algorithm = "fixed_window"
limit = 42
burst = 3
window_sec = 15
require_authenticated = true
match_module = "certification_server"
match_methods = "POST, GET"
match_scopes = "scope-a, scope-b"
match_tags = "env=test, team=core"
`

	if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := system.LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("expected config to load, got error: %v", err)
	}
	if cfg.AuthControl == nil {
		t.Fatalf("expected auth control config to be present")
	}
	if cfg.MySQL == nil || cfg.Redis == nil || cfg.Etcd == nil {
		t.Fatalf("expected mysql, redis and etcd configs to be present: %+v", cfg)
	}
	if cfg.MySQL.DSN == "" || len(cfg.MySQL.DSNs) != 2 {
		t.Fatalf("expected mysql dsn fields to be parsed, got %+v", cfg.MySQL)
	}
	if cfg.MySQL.ConnMaxLifetime != 30*time.Minute || cfg.MySQL.ConnMaxIdleTime != 10*time.Minute || cfg.MySQL.OpTimeout != 3*time.Second {
		t.Fatalf("expected mysql duration fields to be parsed, got %+v", cfg.MySQL)
	}
	if cfg.MySQL.CircuitBreaker == nil || cfg.MySQL.CircuitBreaker.FailureThreshold != 5 || cfg.MySQL.CircuitBreaker.RecoveryTimeout != 10*time.Second || cfg.MySQL.CircuitBreaker.HalfOpenMaxCalls != 1 {
		t.Fatalf("expected mysql circuit breaker fields to be parsed, got %+v", cfg.MySQL.CircuitBreaker)
	}
	if cfg.Redis.Mode != system.RedisModeStandalone || cfg.Redis.Addr != "127.0.0.1:6379" || cfg.Redis.RouteByLatency != true {
		t.Fatalf("expected redis scalar fields to be parsed, got %+v", cfg.Redis)
	}
	if cfg.Redis.DialTimeout != 2*time.Second || cfg.Redis.ReadTimeout != 2*time.Second || cfg.Redis.WriteTimeout != 2*time.Second || cfg.Redis.DefaultTTL != 24*time.Hour {
		t.Fatalf("expected redis duration fields to be parsed, got %+v", cfg.Redis)
	}
	if cfg.Redis.CircuitBreaker == nil || cfg.Redis.CircuitBreaker.FailureThreshold != 5 || cfg.Redis.CircuitBreaker.RecoveryTimeout != 10*time.Second || cfg.Redis.CircuitBreaker.HalfOpenMaxCalls != 1 {
		t.Fatalf("expected redis circuit breaker fields to be parsed, got %+v", cfg.Redis.CircuitBreaker)
	}
	if len(cfg.Etcd.Endpoints) != 2 || cfg.Etcd.Username != "etcd-user" || cfg.Etcd.Password != "etcd-pass" {
		t.Fatalf("expected etcd scalar fields to be parsed, got %+v", cfg.Etcd)
	}
	if cfg.Etcd.DialTimeout != 5*time.Second || cfg.Etcd.AutoSyncInterval != 30*time.Second || cfg.Etcd.OpTimeout != 3*time.Second {
		t.Fatalf("expected etcd duration fields to be parsed, got %+v", cfg.Etcd)
	}
	if cfg.Etcd.CircuitBreaker == nil || cfg.Etcd.CircuitBreaker.FailureThreshold != 6 || cfg.Etcd.CircuitBreaker.RecoveryTimeout != 25*time.Second || cfg.Etcd.CircuitBreaker.HalfOpenMaxCalls != 2 {
		t.Fatalf("expected etcd circuit breaker fields to be parsed, got %+v", cfg.Etcd.CircuitBreaker)
	}
	if !cfg.AuthControl.Enabled {
		t.Fatalf("expected enabled flag to be parsed")
	}
	if cfg.AuthControl.RuleID != "local-auth-control" {
		t.Fatalf("expected rule id to be parsed, got %q", cfg.AuthControl.RuleID)
	}
	if cfg.AuthControl.Limit != 42 || cfg.AuthControl.Burst != 3 || cfg.AuthControl.WindowSec != 15 {
		t.Fatalf("expected auth control numeric fields to be parsed, got %+v", cfg.AuthControl)
	}
	if cfg.AuthControl.Scope != authmodel.RateLimitScopeAuth {
		t.Fatalf("expected scope auth, got %s", cfg.AuthControl.Scope)
	}
	if cfg.AuthControl.Subject != authmodel.SubjectComposite {
		t.Fatalf("expected subject composite, got %s", cfg.AuthControl.Subject)
	}
	if len(cfg.AuthControl.MatchMethods) != 2 {
		t.Fatalf("expected two match methods, got %#v", cfg.AuthControl.MatchMethods)
	}
	if cfg.AuthControl.MatchTags["env"] != "test" || cfg.AuthControl.MatchTags["team"] != "core" {
		t.Fatalf("expected match tags to be parsed, got %#v", cfg.AuthControl.MatchTags)
	}

	normalized := cfg.Normalized("fallback-instance")
	if normalized.AuthControl == nil {
		t.Fatalf("expected normalized auth control config to be present")
	}
	if normalized.AuthControl.MatchModule != "certification_server" {
		t.Fatalf("expected match module to remain certification_server, got %q", normalized.AuthControl.MatchModule)
	}
	if normalized.AuthControl.MatchMethods[0] != "POST" || normalized.AuthControl.MatchMethods[1] != "GET" {
		t.Fatalf("expected normalized match methods to preserve order, got %#v", normalized.AuthControl.MatchMethods)
	}
	if normalized.AuthControl.MatchScopes[0] != "scope-a" || normalized.AuthControl.MatchScopes[1] != "scope-b" {
		t.Fatalf("expected normalized match scopes, got %#v", normalized.AuthControl.MatchScopes)
	}
	if normalized.AuthControl.MatchTags["env"] != "test" {
		t.Fatalf("expected normalized match tags to be preserved, got %#v", normalized.AuthControl.MatchTags)
	}
}
