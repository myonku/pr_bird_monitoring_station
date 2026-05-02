package system

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func loadProjectConfig(cfgPath string) (*ProjectConfig, error) {
	path := strings.TrimSpace(cfgPath)
	if path == "" {
		path = "settings.toml"
	}

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

		switch section {
		case "runtime":
			if err := assignRuntimeField(cfg, key, value, lineNo); err != nil {
				return err
			}
		case "auth":
			if err := assignAuthField(cfg, key, value, lineNo); err != nil {
				return err
			}
		case "mysql":
			if err := assignMySQLField(cfg, key, value, lineNo); err != nil {
				return err
			}
		case "redis":
			if err := assignRedisField(cfg, key, value, lineNo); err != nil {
				return err
			}
		case "etcd":
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
	case "service_name", "entity_name":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [runtime].service_name at line %d: %w", lineNo, err)
		}
		cfg.Runtime.ServiceName = parsed
	case "instance_id", "entity_id", "service_id":
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
	case "http_listen_host", "http_host", "listen_host", "host":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [runtime].http_listen_host at line %d: %w", lineNo, err)
		}
		cfg.Runtime.HTTPListenHost = parsed
	case "http_listen_port", "http_port":
		parsed, err := parseTOMLInt(value)
		if err != nil {
			return fmt.Errorf("invalid [runtime].http_listen_port at line %d: %w", lineNo, err)
		}
		cfg.Runtime.HTTPListenPort = parsed
	}

	return nil
}

func assignAuthField(cfg *ProjectConfig, key, value string, lineNo int) error {
	if cfg.Auth == nil {
		cfg.Auth = &AuthConfig{}
	}

	switch key {
	case "secret_key_dir", "secret_dir":
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
	}

	return nil
}

func assignMySQLField(cfg *ProjectConfig, key, value string, lineNo int) error {
	if cfg.MySQL == nil {
		cfg.MySQL = &MySQLConfig{}
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

func parseTOMLInt64(raw string) (int64, error) {
	value, err := parseTOMLString(raw)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(value), 10, 64)
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

func parseTOMLDuration(raw string) (time.Duration, error) {
	value, err := parseTOMLString(raw)
	if err != nil {
		return 0, err
	}
	if strings.TrimSpace(value) == "" {
		return 0, nil
	}
	return time.ParseDuration(strings.TrimSpace(value))
}
