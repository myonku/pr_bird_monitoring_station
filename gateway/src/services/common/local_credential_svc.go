package common

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	commonif "gateway/src/iface/common"
	authmodel "gateway/src/models/auth"
	modelsystem "gateway/src/models/system"
	"gateway/src/repo"

	"github.com/redis/go-redis/v9"
)

const (
	defaultLocalCredentialKeyPrefix = "bms/local_credentials"
	defaultLocalCredentialTTL       = 24 * time.Hour
)

var _ commonif.ILocalCredentialManager = (*LocalCredentialService)(nil)

// LocalCredentialService 负责网关本模块凭证快照的 Redis 持久化与状态变更。
type LocalCredentialService struct {
	redis     *repo.RedisClient
	keyPrefix string
}

// NewLocalCredentialService 创建本地凭证管理服务。
func NewLocalCredentialService(redisClient *repo.RedisClient, keyPrefix string) commonif.ILocalCredentialManager {
	resolvedPrefix := strings.TrimSpace(keyPrefix)
	if resolvedPrefix == "" {
		resolvedPrefix = defaultLocalCredentialKeyPrefix
	}
	return &LocalCredentialService{
		redis:     redisClient,
		keyPrefix: strings.Trim(resolvedPrefix, "/"),
	}
}

func (s *LocalCredentialService) SaveBootstrapCredential(
	ctx context.Context,
	snapshot *commonif.ModuleCredentialSnapshot,
) (string, error) {
	if s.redis == nil {
		return "", &modelsystem.ErrNilRedisClient
	}
	if snapshot == nil {
		return "", &modelsystem.ErrModuleCredentialBootstrapRequestNeeded
	}

	principalID := strings.TrimSpace(snapshot.PrincipalID)
	if principalID == "" {
		return "", &modelsystem.ErrIdentityPrincipalRequired
	}

	now := time.Now()
	if snapshot.Stage == "" {
		snapshot.Stage = authmodel.BootstrapStageReady
	}
	if snapshot.IssuedAt.IsZero() {
		snapshot.IssuedAt = now
	}
	if snapshot.ExpiresAt.IsZero() {
		snapshot.ExpiresAt = now.Add(15 * time.Minute)
	}
	snapshot.UpdatedAt = now
	if snapshot.Metadata == nil {
		snapshot.Metadata = make(map[string]string)
	}

	payload, err := json.Marshal(snapshot)
	if err != nil {
		return "", fmt.Errorf("marshal module credential snapshot failed: %w", err)
	}

	key := s.credentialKey(principalID)
	if err = s.redis.Set(ctx, key, string(payload), resolveCredentialTTL(snapshot.ExpiresAt, now)); err != nil {
		return "", err
	}
	return key, nil
}

func (s *LocalCredentialService) LoadActiveCredential(
	ctx context.Context,
	principalID string,
) (*commonif.ModuleCredentialSnapshot, error) {
	if s.redis == nil {
		return nil, &modelsystem.ErrNilRedisClient
	}
	resolvedPrincipalID := strings.TrimSpace(principalID)
	if resolvedPrincipalID == "" {
		return nil, &modelsystem.ErrIdentityPrincipalRequired
	}

	raw, err := s.redis.Get(ctx, s.credentialKey(resolvedPrincipalID))
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, err
	}

	var snapshot commonif.ModuleCredentialSnapshot
	if err = json.Unmarshal([]byte(raw), &snapshot); err != nil {
		return nil, fmt.Errorf("unmarshal module credential snapshot failed: %w", err)
	}
	if snapshot.Metadata == nil {
		snapshot.Metadata = make(map[string]string)
	}
	return &snapshot, nil
}

func (s *LocalCredentialService) MarkCredentialExpired(
	ctx context.Context,
	principalID string,
	reason string,
) error {
	snapshot, err := s.LoadActiveCredential(ctx, principalID)
	if err != nil {
		return err
	}
	if snapshot == nil {
		return nil
	}
	if snapshot.Metadata == nil {
		snapshot.Metadata = make(map[string]string)
	}
	snapshot.Stage = authmodel.BootstrapStageUninitialized
	snapshot.Metadata["credential_status"] = "expired"
	snapshot.Metadata["credential_reason"] = strings.TrimSpace(reason)
	_, err = s.SaveBootstrapCredential(ctx, snapshot)
	return err
}

func (s *LocalCredentialService) RevokeCredential(
	ctx context.Context,
	principalID string,
	reason string,
) error {
	_ = reason
	if s.redis == nil {
		return &modelsystem.ErrNilRedisClient
	}
	resolvedPrincipalID := strings.TrimSpace(principalID)
	if resolvedPrincipalID == "" {
		return &modelsystem.ErrIdentityPrincipalRequired
	}

	_, err := s.redis.Del(ctx, s.credentialKey(resolvedPrincipalID))
	return err
}

func (s *LocalCredentialService) credentialKey(principalID string) string {
	return fmt.Sprintf("/%s/%s", s.keyPrefix, strings.TrimSpace(principalID))
}

func resolveCredentialTTL(expiresAt time.Time, now time.Time) time.Duration {
	if !expiresAt.IsZero() && expiresAt.After(now) {
		return expiresAt.Sub(now)
	}
	return defaultLocalCredentialTTL
}

// IsCredentialValidForDiscovery 判断当前模块凭证是否足以参与服务发现。
func IsCredentialValidForDiscovery(snapshot *commonif.ModuleCredentialSnapshot, now time.Time) bool {
	if snapshot == nil {
		return false
	}
	if strings.TrimSpace(snapshot.PrincipalID) == "" {
		return false
	}
	if snapshot.Stage != authmodel.BootstrapStageReady {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(snapshot.Metadata["credential_status"]), "revoked") {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(snapshot.Metadata["credential_status"]), "expired") {
		return false
	}
	if strings.TrimSpace(snapshot.RefreshTokenRaw) == "" {
		return false
	}

	expiresAt := snapshot.ExpiresAt
	if raw := strings.TrimSpace(snapshot.Metadata["refresh_expires_at_ms"]); raw != "" {
		if millis, err := strconv.ParseInt(raw, 10, 64); err == nil && millis > 0 {
			expiresAt = time.UnixMilli(millis)
		}
	}
	if !expiresAt.IsZero() && !expiresAt.After(now) {
		return false
	}

	return true
}
