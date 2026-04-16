package system

import (
	"bufio"
	authmodel "certification_server/src/models/auth"
	commonmodel "certification_server/src/models/common"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultSettingsPath 是认证中心默认配置文件路径。
	DefaultSettingsPath = "settings.toml"
	// SettingsPathEnvVar 定义认证中心配置路径的环境变量名。
	SettingsPathEnvVar = "CERTIFICATION_SETTINGS_PATH"
)

// ResolveConfigPath 解析认证中心配置文件路径，优先级：显式参数 > 环境变量 > 默认路径。
func ResolveConfigPath(cfgPath string) string {
	path := strings.TrimSpace(cfgPath)
	if path != "" {
		return path
	}

	envPath := strings.TrimSpace(os.Getenv(SettingsPathEnvVar))
	if envPath != "" {
		return envPath
	}

	return DefaultSettingsPath
}

// LoadConfig 从 TOML 文件加载认证中心配置。
func LoadConfig(cfgPath string) (*ProjectConfig, error) {
	path := ResolveConfigPath(cfgPath)

	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &ProjectConfig{}, nil
		}
		return nil, fmt.Errorf("read config file failed: %w", err)
	}

	cfg := &ProjectConfig{}
	if err := parseProjectConfigFromTOML(string(raw), cfg); err != nil {
		return nil, fmt.Errorf("parse config file failed: %w", err)
	}
	return cfg, nil
}

func parseProjectConfigFromTOML(content string, cfg *ProjectConfig) error {
	if cfg == nil {
		return fmt.Errorf("project config is nil")
	}

	scanner := bufio.NewScanner(strings.NewReader(content))
	section := ""
	lineNo := 0

	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(stripTOMLComment(scanner.Text()))
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}

		key, value, ok := splitTOMLKeyValue(line)
		if !ok {
			continue
		}

		if section == "runtime" {
			if err := assignRuntimeField(cfg, key, value, lineNo); err != nil {
				return err
			}
		}

		if section == "auth" {
			if err := assignAuthField(cfg, key, value, lineNo); err != nil {
				return err
			}
		}

		if section == "auth_control" {
			if err := assignAuthControlField(cfg, key, value, lineNo); err != nil {
				return err
			}
		}

		if section == "mysql" {
			if err := assignMySQLField(cfg, key, value, lineNo); err != nil {
				return err
			}
		}

		if section == "redis" {
			if err := assignRedisField(cfg, key, value, lineNo); err != nil {
				return err
			}
		}

		if section == "etcd" {
			if err := assignEtcdField(cfg, key, value, lineNo); err != nil {
				return err
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan config failed: %w", err)
	}
	return nil
}

func assignRuntimeField(cfg *ProjectConfig, key, value string, lineNo int) error {
	if cfg.Runtime == nil {
		cfg.Runtime = &RuntimeConfig{}
	}

	switch key {
	case "entity_type":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [runtime].entity_type at line %d: %w", lineNo, err)
		}
		cfg.Runtime.EntityType = parsed
	case "service_name":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [runtime].service_name at line %d: %w", lineNo, err)
		}
		cfg.Runtime.ServiceName = parsed
	case "instance_id":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [runtime].instance_id at line %d: %w", lineNo, err)
		}
		cfg.Runtime.InstanceID = parsed
	case "run_mode":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [runtime].run_mode at line %d: %w", lineNo, err)
		}
		mode, ok := parseRuntimeRunMode(parsed)
		if !ok {
			return fmt.Errorf("invalid [runtime].run_mode at line %d: unsupported value %q", lineNo, parsed)
		}
		cfg.Runtime.RunMode = mode
	case "grpc_listen_host":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [runtime].grpc_listen_host at line %d: %w", lineNo, err)
		}
		cfg.Runtime.GRPCListenHost = parsed
	case "grpc_listen_port":
		parsed, err := parseTOMLInt(value)
		if err != nil {
			return fmt.Errorf("invalid [runtime].grpc_listen_port at line %d: %w", lineNo, err)
		}
		cfg.Runtime.GRPCListenPort = parsed
	default:
		return fmt.Errorf("unsupported [runtime] key %q at line %d", key, lineNo)
	}

	return nil
}

func assignAuthField(cfg *ProjectConfig, key, value string, lineNo int) error {
	if cfg.Auth == nil {
		cfg.Auth = &AuthConfig{}
	}

	switch key {
	case "secret_key_dir":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [auth].secret_key_dir at line %d: %w", lineNo, err)
		}
		cfg.Auth.SecretKeyDir = parsed
	case "active_key_id":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [auth].active_key_id at line %d: %w", lineNo, err)
		}
		cfg.Auth.ActiveKeyID = parsed
	default:
		return fmt.Errorf("unsupported [auth] key %q at line %d", key, lineNo)
	}

	return nil
}

func assignAuthControlField(cfg *ProjectConfig, key, value string, lineNo int) error {
	if cfg.AuthControl == nil {
		cfg.AuthControl = &AuthControlConfig{}
	}

	switch key {
	case "enabled":
		parsed, err := parseTOMLBool(value)
		if err != nil {
			return fmt.Errorf("invalid [auth_control].enabled at line %d: %w", lineNo, err)
		}
		cfg.AuthControl.Enabled = parsed
	case "rule_id":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [auth_control].rule_id at line %d: %w", lineNo, err)
		}
		cfg.AuthControl.RuleID = parsed
	case "scope":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [auth_control].scope at line %d: %w", lineNo, err)
		}
		cfg.AuthControl.Scope = normalizeRateLimitScope(parsed)
	case "subject":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [auth_control].subject at line %d: %w", lineNo, err)
		}
		cfg.AuthControl.Subject = normalizeRateLimitSubjectType(parsed)
	case "algorithm":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [auth_control].algorithm at line %d: %w", lineNo, err)
		}
		cfg.AuthControl.Algorithm = normalizeRateLimitAlgorithm(parsed)
	case "limit":
		parsed, err := parseTOMLInt(value)
		if err != nil {
			return fmt.Errorf("invalid [auth_control].limit at line %d: %w", lineNo, err)
		}
		cfg.AuthControl.Limit = int64(parsed)
	case "burst":
		parsed, err := parseTOMLInt(value)
		if err != nil {
			return fmt.Errorf("invalid [auth_control].burst at line %d: %w", lineNo, err)
		}
		cfg.AuthControl.Burst = int64(parsed)
	case "window_sec":
		parsed, err := parseTOMLInt(value)
		if err != nil {
			return fmt.Errorf("invalid [auth_control].window_sec at line %d: %w", lineNo, err)
		}
		cfg.AuthControl.WindowSec = int64(parsed)
	case "require_authenticated":
		parsed, err := parseTOMLBool(value)
		if err != nil {
			return fmt.Errorf("invalid [auth_control].require_authenticated at line %d: %w", lineNo, err)
		}
		cfg.AuthControl.RequireAuthenticated = parsed
	case "match_module":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [auth_control].match_module at line %d: %w", lineNo, err)
		}
		cfg.AuthControl.MatchModule = parsed
	case "match_action":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [auth_control].match_action at line %d: %w", lineNo, err)
		}
		cfg.AuthControl.MatchAction = parsed
	case "match_route":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [auth_control].match_route at line %d: %w", lineNo, err)
		}
		cfg.AuthControl.MatchRoute = parsed
	case "match_methods":
		parsed, err := parseTOMLStringList(value)
		if err != nil {
			return fmt.Errorf("invalid [auth_control].match_methods at line %d: %w", lineNo, err)
		}
		cfg.AuthControl.MatchMethods = parsed
	case "match_entity_types":
		parsed, err := parseTOMLEntityTypeList(value)
		if err != nil {
			return fmt.Errorf("invalid [auth_control].match_entity_types at line %d: %w", lineNo, err)
		}
		cfg.AuthControl.MatchEntityTypes = parsed
	case "match_token_types":
		parsed, err := parseTOMLTokenTypeList(value)
		if err != nil {
			return fmt.Errorf("invalid [auth_control].match_token_types at line %d: %w", lineNo, err)
		}
		cfg.AuthControl.MatchTokenTypes = parsed
	case "match_gateway_ids":
		parsed, err := parseTOMLStringList(value)
		if err != nil {
			return fmt.Errorf("invalid [auth_control].match_gateway_ids at line %d: %w", lineNo, err)
		}
		cfg.AuthControl.MatchGatewayIDs = parsed
	case "match_source_services":
		parsed, err := parseTOMLStringList(value)
		if err != nil {
			return fmt.Errorf("invalid [auth_control].match_source_services at line %d: %w", lineNo, err)
		}
		cfg.AuthControl.MatchSourceServices = parsed
	case "match_target_services":
		parsed, err := parseTOMLStringList(value)
		if err != nil {
			return fmt.Errorf("invalid [auth_control].match_target_services at line %d: %w", lineNo, err)
		}
		cfg.AuthControl.MatchTargetServices = parsed
	case "match_scopes":
		parsed, err := parseTOMLStringList(value)
		if err != nil {
			return fmt.Errorf("invalid [auth_control].match_scopes at line %d: %w", lineNo, err)
		}
		cfg.AuthControl.MatchScopes = parsed
	case "match_tags":
		parsed, err := parseTOMLTagMap(value)
		if err != nil {
			return fmt.Errorf("invalid [auth_control].match_tags at line %d: %w", lineNo, err)
		}
		cfg.AuthControl.MatchTags = parsed
	default:
		return fmt.Errorf("unsupported [auth_control] key %q at line %d", key, lineNo)
	}

	return nil
}

func assignMySQLField(cfg *ProjectConfig, key, value string, lineNo int) error {
	if cfg.MySQL == nil {
		cfg.MySQL = &MySQLConfig{}
	}

	if handled, err := assignCircuitBreakerField(&cfg.MySQL.CircuitBreaker, "[mysql]", key, value, lineNo); handled || err != nil {
		return err
	}

	switch key {
	case "dsn":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [mysql].dsn at line %d: %w", lineNo, err)
		}
		cfg.MySQL.DSN = parsed
	case "dsns":
		parsed, err := parseTOMLStringList(value)
		if err != nil {
			return fmt.Errorf("invalid [mysql].dsns at line %d: %w", lineNo, err)
		}
		cfg.MySQL.DSNs = parsed
	case "max_open_conns":
		parsed, err := parseTOMLInt(value)
		if err != nil {
			return fmt.Errorf("invalid [mysql].max_open_conns at line %d: %w", lineNo, err)
		}
		cfg.MySQL.MaxOpenConns = parsed
	case "max_idle_conns":
		parsed, err := parseTOMLInt(value)
		if err != nil {
			return fmt.Errorf("invalid [mysql].max_idle_conns at line %d: %w", lineNo, err)
		}
		cfg.MySQL.MaxIdleConns = parsed
	case "conn_max_lifetime":
		parsed, err := parseTOMLDuration(value)
		if err != nil {
			return fmt.Errorf("invalid [mysql].conn_max_lifetime at line %d: %w", lineNo, err)
		}
		cfg.MySQL.ConnMaxLifetime = parsed
	case "conn_max_idle_time":
		parsed, err := parseTOMLDuration(value)
		if err != nil {
			return fmt.Errorf("invalid [mysql].conn_max_idle_time at line %d: %w", lineNo, err)
		}
		cfg.MySQL.ConnMaxIdleTime = parsed
	case "op_timeout":
		parsed, err := parseTOMLDuration(value)
		if err != nil {
			return fmt.Errorf("invalid [mysql].op_timeout at line %d: %w", lineNo, err)
		}
		cfg.MySQL.OpTimeout = parsed
	default:
		return fmt.Errorf("unsupported [mysql] key %q at line %d", key, lineNo)
	}

	return nil
}

func assignRedisField(cfg *ProjectConfig, key, value string, lineNo int) error {
	if cfg.Redis == nil {
		cfg.Redis = &RedisClientConfig{}
	}

	if handled, err := assignCircuitBreakerField(&cfg.Redis.CircuitBreaker, "[redis]", key, value, lineNo); handled || err != nil {
		return err
	}

	switch key {
	case "mode":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [redis].mode at line %d: %w", lineNo, err)
		}
		switch strings.ToLower(strings.TrimSpace(parsed)) {
		case "", string(RedisModeStandalone):
			cfg.Redis.Mode = RedisModeStandalone
		case string(RedisModeSentinel):
			cfg.Redis.Mode = RedisModeSentinel
		case string(RedisModeCluster):
			cfg.Redis.Mode = RedisModeCluster
		default:
			return fmt.Errorf("invalid [redis].mode at line %d: unsupported value %q", lineNo, parsed)
		}
	case "addr":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [redis].addr at line %d: %w", lineNo, err)
		}
		cfg.Redis.Addr = parsed
	case "addrs":
		parsed, err := parseTOMLStringList(value)
		if err != nil {
			return fmt.Errorf("invalid [redis].addrs at line %d: %w", lineNo, err)
		}
		cfg.Redis.Addrs = parsed
	case "master_name":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [redis].master_name at line %d: %w", lineNo, err)
		}
		cfg.Redis.MasterName = parsed
	case "username":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [redis].username at line %d: %w", lineNo, err)
		}
		cfg.Redis.Username = parsed
	case "password":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [redis].password at line %d: %w", lineNo, err)
		}
		cfg.Redis.Password = parsed
	case "sentinel_username":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [redis].sentinel_username at line %d: %w", lineNo, err)
		}
		cfg.Redis.SentinelUsername = parsed
	case "sentinel_password":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [redis].sentinel_password at line %d: %w", lineNo, err)
		}
		cfg.Redis.SentinelPassword = parsed
	case "db":
		parsed, err := parseTOMLInt(value)
		if err != nil {
			return fmt.Errorf("invalid [redis].db at line %d: %w", lineNo, err)
		}
		cfg.Redis.DB = parsed
	case "max_retries":
		parsed, err := parseTOMLInt(value)
		if err != nil {
			return fmt.Errorf("invalid [redis].max_retries at line %d: %w", lineNo, err)
		}
		cfg.Redis.MaxRetries = parsed
	case "pool_size":
		parsed, err := parseTOMLInt(value)
		if err != nil {
			return fmt.Errorf("invalid [redis].pool_size at line %d: %w", lineNo, err)
		}
		cfg.Redis.PoolSize = parsed
	case "min_idle_conns":
		parsed, err := parseTOMLInt(value)
		if err != nil {
			return fmt.Errorf("invalid [redis].min_idle_conns at line %d: %w", lineNo, err)
		}
		cfg.Redis.MinIdleConns = parsed
	case "dial_timeout":
		parsed, err := parseTOMLDuration(value)
		if err != nil {
			return fmt.Errorf("invalid [redis].dial_timeout at line %d: %w", lineNo, err)
		}
		cfg.Redis.DialTimeout = parsed
	case "read_timeout":
		parsed, err := parseTOMLDuration(value)
		if err != nil {
			return fmt.Errorf("invalid [redis].read_timeout at line %d: %w", lineNo, err)
		}
		cfg.Redis.ReadTimeout = parsed
	case "write_timeout":
		parsed, err := parseTOMLDuration(value)
		if err != nil {
			return fmt.Errorf("invalid [redis].write_timeout at line %d: %w", lineNo, err)
		}
		cfg.Redis.WriteTimeout = parsed
	case "read_only":
		parsed, err := parseTOMLBool(value)
		if err != nil {
			return fmt.Errorf("invalid [redis].read_only at line %d: %w", lineNo, err)
		}
		cfg.Redis.ReadOnly = parsed
	case "route_by_latency":
		parsed, err := parseTOMLBool(value)
		if err != nil {
			return fmt.Errorf("invalid [redis].route_by_latency at line %d: %w", lineNo, err)
		}
		cfg.Redis.RouteByLatency = parsed
	case "route_randomly":
		parsed, err := parseTOMLBool(value)
		if err != nil {
			return fmt.Errorf("invalid [redis].route_randomly at line %d: %w", lineNo, err)
		}
		cfg.Redis.RouteRandomly = parsed
	case "op_timeout":
		parsed, err := parseTOMLDuration(value)
		if err != nil {
			return fmt.Errorf("invalid [redis].op_timeout at line %d: %w", lineNo, err)
		}
		cfg.Redis.OpTimeout = parsed
	case "default_ttl":
		parsed, err := parseTOMLDuration(value)
		if err != nil {
			return fmt.Errorf("invalid [redis].default_ttl at line %d: %w", lineNo, err)
		}
		cfg.Redis.DefaultTTL = parsed
	default:
		return fmt.Errorf("unsupported [redis] key %q at line %d", key, lineNo)
	}

	return nil
}

func assignEtcdField(cfg *ProjectConfig, key, value string, lineNo int) error {
	if cfg.Etcd == nil {
		cfg.Etcd = &EtcdClientConfig{}
	}

	if handled, err := assignCircuitBreakerField(&cfg.Etcd.CircuitBreaker, "[etcd]", key, value, lineNo); handled || err != nil {
		return err
	}

	switch key {
	case "endpoints":
		parsed, err := parseTOMLStringList(value)
		if err != nil {
			return fmt.Errorf("invalid [etcd].endpoints at line %d: %w", lineNo, err)
		}
		cfg.Etcd.Endpoints = parsed
	case "username":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [etcd].username at line %d: %w", lineNo, err)
		}
		cfg.Etcd.Username = parsed
	case "password":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [etcd].password at line %d: %w", lineNo, err)
		}
		cfg.Etcd.Password = parsed
	case "dial_timeout":
		parsed, err := parseTOMLDuration(value)
		if err != nil {
			return fmt.Errorf("invalid [etcd].dial_timeout at line %d: %w", lineNo, err)
		}
		cfg.Etcd.DialTimeout = parsed
	case "auto_sync_interval":
		parsed, err := parseTOMLDuration(value)
		if err != nil {
			return fmt.Errorf("invalid [etcd].auto_sync_interval at line %d: %w", lineNo, err)
		}
		cfg.Etcd.AutoSyncInterval = parsed
	case "op_timeout":
		parsed, err := parseTOMLDuration(value)
		if err != nil {
			return fmt.Errorf("invalid [etcd].op_timeout at line %d: %w", lineNo, err)
		}
		cfg.Etcd.OpTimeout = parsed
	default:
		return fmt.Errorf("unsupported [etcd] key %q at line %d", key, lineNo)
	}

	return nil
}

func assignCircuitBreakerField(target **CircuitBreakerConfig, sectionName, key, value string, lineNo int) (bool, error) {
	if !strings.HasPrefix(key, "circuit_breaker_") {
		return false, nil
	}
	if target == nil {
		return true, fmt.Errorf("%s circuit breaker target is nil", sectionName)
	}
	if *target == nil {
		*target = &CircuitBreakerConfig{}
	}

	switch key {
	case "circuit_breaker_failure_threshold":
		parsed, err := parseTOMLInt(value)
		if err != nil {
			return true, fmt.Errorf("invalid %s.circuit_breaker_failure_threshold at line %d: %w", sectionName, lineNo, err)
		}
		(*target).FailureThreshold = parsed
	case "circuit_breaker_recovery_timeout":
		parsed, err := parseTOMLDuration(value)
		if err != nil {
			return true, fmt.Errorf("invalid %s.circuit_breaker_recovery_timeout at line %d: %w", sectionName, lineNo, err)
		}
		(*target).RecoveryTimeout = parsed
	case "circuit_breaker_half_open_max_calls":
		parsed, err := parseTOMLInt(value)
		if err != nil {
			return true, fmt.Errorf("invalid %s.circuit_breaker_half_open_max_calls at line %d: %w", sectionName, lineNo, err)
		}
		(*target).HalfOpenMaxCalls = parsed
	default:
		return true, fmt.Errorf("unsupported %s key %q at line %d", sectionName, key, lineNo)
	}

	return true, nil
}

func parseTOMLBool(raw string) (bool, error) {
	value, err := parseTOMLString(raw)
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1", "yes", "on":
		return true, nil
	case "false", "0", "no", "off", "":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean value %q", value)
	}
}

func parseTOMLStringList(raw string) ([]string, error) {
	value, err := parseTOMLString(raw)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func parseTOMLEntityTypeList(raw string) ([]commonmodel.EntityType, error) {
	items, err := parseTOMLStringList(raw)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, nil
	}
	out := make([]commonmodel.EntityType, 0, len(items))
	for _, item := range items {
		switch commonmodel.EntityType(strings.ToLower(strings.TrimSpace(item))) {
		case commonmodel.EntityUser, commonmodel.EntityDevice, commonmodel.EntityService:
			out = append(out, commonmodel.EntityType(strings.ToLower(strings.TrimSpace(item))))
		default:
			return nil, fmt.Errorf("unsupported entity type %q", item)
		}
	}
	return out, nil
}

func parseTOMLTokenTypeList(raw string) ([]authmodel.TokenType, error) {
	items, err := parseTOMLStringList(raw)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, nil
	}
	out := make([]authmodel.TokenType, 0, len(items))
	for _, item := range items {
		switch authmodel.TokenType(strings.ToLower(strings.TrimSpace(item))) {
		case authmodel.TokenAccess, authmodel.TokenRefresh, authmodel.TokenService, authmodel.TokenDownstream:
			out = append(out, authmodel.TokenType(strings.ToLower(strings.TrimSpace(item))))
		default:
			return nil, fmt.Errorf("unsupported token type %q", item)
		}
	}
	return out, nil
}

func parseTOMLTagMap(raw string) (map[string]string, error) {
	items, err := parseTOMLStringList(raw)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return map[string]string{}, nil
	}
	out := make(map[string]string, len(items))
	for _, item := range items {
		parts := strings.SplitN(item, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid tag pair %q", item)
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "" || value == "" {
			return nil, fmt.Errorf("invalid tag pair %q", item)
		}
		out[key] = value
	}
	return out, nil
}

func splitTOMLKeyValue(line string) (string, string, bool) {
	idx := strings.Index(line, "=")
	if idx <= 0 {
		return "", "", false
	}

	key := strings.ToLower(strings.TrimSpace(line[:idx]))
	value := strings.TrimSpace(line[idx+1:])
	if key == "" {
		return "", "", false
	}
	return key, value, true
}

func stripTOMLComment(line string) string {
	inQuotes := false
	for i, r := range line {
		switch r {
		case '"':
			inQuotes = !inQuotes
		case '#':
			if !inQuotes {
				return line[:i]
			}
		}
	}
	return line
}

func parseTOMLString(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil
	}

	if strings.HasPrefix(value, "\"") {
		if !strings.HasSuffix(value, "\"") {
			return "", fmt.Errorf("unterminated quoted string")
		}
		parsed, err := strconv.Unquote(value)
		if err != nil {
			return "", err
		}
		return parsed, nil
	}

	return value, nil
}

func parseTOMLInt(raw string) (int, error) {
	value, err := parseTOMLString(raw)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(value))
}

func parseTOMLDuration(raw string) (time.Duration, error) {
	value, err := parseTOMLString(raw)
	if err != nil {
		return 0, err
	}
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 0, nil
	}
	if duration, parseErr := time.ParseDuration(trimmed); parseErr == nil {
		return duration, nil
	}
	seconds, parseErr := strconv.ParseInt(trimmed, 10, 64)
	if parseErr != nil {
		return 0, fmt.Errorf("invalid duration value %q", value)
	}
	return time.Duration(seconds) * time.Second, nil
}
