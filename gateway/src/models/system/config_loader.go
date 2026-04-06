package system

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
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
		case "internal_assertion":
			if err := assignInternalAssertionField(cfg, key, value, lineNo); err != nil {
				return err
			}
		case "runtime":
			if err := assignRuntimeField(cfg, key, value, lineNo); err != nil {
				return err
			}
		case "auth":
			if err := assignAuthField(cfg, key, value, lineNo); err != nil {
				return err
			}
		case "secret_key":
			if err := assignLegacySecretKeyField(cfg, key, value, lineNo); err != nil {
				return err
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan config failed: %w", err)
	}
	return nil
}

func assignInternalAssertionField(cfg *ProjectConfig, key, value string, lineNo int) error {
	if cfg.InternalAssertion == nil {
		cfg.InternalAssertion = &InternalAssertionConfig{}
	}

	switch key {
	case "enabled":
		parsed, err := parseTOMLBool(value)
		if err != nil {
			return fmt.Errorf("invalid [internal_assertion].enabled at line %d: %w", lineNo, err)
		}
		cfg.InternalAssertion.Enabled = parsed
	case "header_name":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [internal_assertion].header_name at line %d: %w", lineNo, err)
		}
		cfg.InternalAssertion.HeaderName = parsed
	case "ttl_seconds":
		parsed, err := parseTOMLInt64(value)
		if err != nil {
			return fmt.Errorf("invalid [internal_assertion].ttl_seconds at line %d: %w", lineNo, err)
		}
		cfg.InternalAssertion.TTLSeconds = parsed
	case "issuer":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [internal_assertion].issuer at line %d: %w", lineNo, err)
		}
		cfg.InternalAssertion.Issuer = parsed
	case "signature_algorithm":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [internal_assertion].signature_algorithm at line %d: %w", lineNo, err)
		}
		cfg.InternalAssertion.SignatureAlgorithm = parsed
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
	case "entity_id":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [runtime].entity_id at line %d: %w", lineNo, err)
		}
		cfg.Runtime.EntityID = parsed
	case "entity_name":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [runtime].entity_name at line %d: %w", lineNo, err)
		}
		cfg.Runtime.EntityName = parsed
	case "instance_id":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [runtime].instance_id at line %d: %w", lineNo, err)
		}
		cfg.Runtime.InstanceID = parsed
	case "instance_name":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [runtime].instance_name at line %d: %w", lineNo, err)
		}
		cfg.Runtime.InstanceName = parsed
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

func assignLegacySecretKeyField(cfg *ProjectConfig, key, value string, lineNo int) error {
	if cfg.Runtime == nil {
		cfg.Runtime = &RuntimeConfig{}
	}
	if cfg.Auth == nil {
		cfg.Auth = &AuthConfig{}
	}

	switch key {
	case "secret_dir", "secret_key_dir":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [secret_key].secret_dir at line %d: %w", lineNo, err)
		}
		cfg.Auth.SecretKeyDir = parsed
	case "active_key_id":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [secret_key].active_key_id at line %d: %w", lineNo, err)
		}
		cfg.Auth.ActiveKeyID = parsed
	case "entity_type":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [secret_key].entity_type at line %d: %w", lineNo, err)
		}
		cfg.Runtime.EntityType = parsed
	case "entity_id", "service_id":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [secret_key].entity_id at line %d: %w", lineNo, err)
		}
		cfg.Runtime.EntityID = parsed
	case "entity_name", "service_name":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [secret_key].entity_name at line %d: %w", lineNo, err)
		}
		cfg.Runtime.EntityName = parsed
	case "instance_id":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [secret_key].instance_id at line %d: %w", lineNo, err)
		}
		cfg.Runtime.InstanceID = parsed
	case "instance_name":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [secret_key].instance_name at line %d: %w", lineNo, err)
		}
		cfg.Runtime.InstanceName = parsed
	case "enabled", "public_key_ref", "private_key_ref":
		// legacy 兼容字段：新结构下不再使用。
		return nil
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

func parseTOMLBool(raw string) (bool, error) {
	value, err := parseTOMLString(raw)
	if err != nil {
		return false, err
	}
	return strconv.ParseBool(strings.ToLower(strings.TrimSpace(value)))
}

func parseTOMLInt64(raw string) (int64, error) {
	value, err := parseTOMLString(raw)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(value), 10, 64)
}
