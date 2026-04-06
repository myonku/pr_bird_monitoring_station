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
		case "secret_key":
			if err := assignSecretKeyField(cfg, key, value, lineNo); err != nil {
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

func assignSecretKeyField(cfg *ProjectConfig, key, value string, lineNo int) error {
	if cfg.SecretKey == nil {
		cfg.SecretKey = &SecretKeyConfig{}
	}

	switch key {
	case "enabled":
		parsed, err := parseTOMLBool(value)
		if err != nil {
			return fmt.Errorf("invalid [secret_key].enabled at line %d: %w", lineNo, err)
		}
		cfg.SecretKey.Enabled = parsed
	case "secret_dir":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [secret_key].secret_dir at line %d: %w", lineNo, err)
		}
		cfg.SecretKey.SecretDir = parsed
	case "active_key_id":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [secret_key].active_key_id at line %d: %w", lineNo, err)
		}
		cfg.SecretKey.ActiveKeyID = parsed
	case "owner_type":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [secret_key].owner_type at line %d: %w", lineNo, err)
		}
		cfg.SecretKey.OwnerType = parsed
	case "entity_type":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [secret_key].entity_type at line %d: %w", lineNo, err)
		}
		cfg.SecretKey.EntityType = parsed
	case "entity_id":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [secret_key].entity_id at line %d: %w", lineNo, err)
		}
		cfg.SecretKey.EntityID = parsed
	case "entity_name":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [secret_key].entity_name at line %d: %w", lineNo, err)
		}
		cfg.SecretKey.EntityName = parsed
	case "service_id":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [secret_key].service_id at line %d: %w", lineNo, err)
		}
		cfg.SecretKey.ServiceID = parsed
	case "service_name":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [secret_key].service_name at line %d: %w", lineNo, err)
		}
		cfg.SecretKey.ServiceName = parsed
	case "instance_id":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [secret_key].instance_id at line %d: %w", lineNo, err)
		}
		cfg.SecretKey.InstanceID = parsed
	case "instance_name":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [secret_key].instance_name at line %d: %w", lineNo, err)
		}
		cfg.SecretKey.InstanceName = parsed
	case "key_exchange_algorithm":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [secret_key].key_exchange_algorithm at line %d: %w", lineNo, err)
		}
		cfg.SecretKey.KeyExchangeAlgorithm = parsed
	case "signature_algorithm":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [secret_key].signature_algorithm at line %d: %w", lineNo, err)
		}
		cfg.SecretKey.SignatureAlgorithm = parsed
	case "public_key_ref":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [secret_key].public_key_ref at line %d: %w", lineNo, err)
		}
		cfg.SecretKey.PublicKeyRef = parsed
	case "private_key_ref":
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("invalid [secret_key].private_key_ref at line %d: %w", lineNo, err)
		}
		cfg.SecretKey.PrivateKeyRef = parsed
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
