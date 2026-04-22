package orchestration

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	authif "gateway/src/iface/auth"
	commonif "gateway/src/iface/common"
	authmodel "gateway/src/models/auth"
	commonmodel "gateway/src/models/common"
	modelsystem "gateway/src/models/system"
	commonsvc "gateway/src/services/common"
	rpcclient "gateway/src/services/communication/rpc_client"

	"github.com/google/uuid"
)

// BootstrapReadyEnsurer 提供 bootstrap 就绪能力，供 supervisor 在凭证失效时重建凭证。
type BootstrapReadyEnsurer interface {
	EnsureReady(ctx context.Context, req *BootstrapStartupRequest) (*BootstrapStartupResult, error)
}

// TokenRefreshClient 提供 token refresh 的最小调用能力，便于注入与测试。
type TokenRefreshClient interface {
	RefreshTokenBundle(ctx context.Context, req *authif.TokenRefreshRequest) (*authmodel.TokenBundle, error)
}

// CredentialDiscoverySupervisorService 周期性检测本地凭证状态，并控制服务发现参与。
type CredentialDiscoverySupervisorService struct {
	runtime            modelsystem.RuntimeConfig
	startupParams      modelsystem.SecretKeyStartupParams
	localCredentialMgr commonif.ILocalCredentialManager
	registryMgr        commonif.IRegistryManager
	bootstrapEnsurer   BootstrapReadyEnsurer
	refreshFactory     func(endpoint string) TokenRefreshClient
	instance           *commonmodel.ServiceInstance
	registryTTLSeconds int64
	interval           time.Duration

	mu         sync.Mutex
	registered bool
}

// NewCredentialDiscoverySupervisorService 创建凭证驱动的服务发现监督器。
func NewCredentialDiscoverySupervisorService(
	runtime modelsystem.RuntimeConfig,
	startupParams modelsystem.SecretKeyStartupParams,
	localCredentialMgr commonif.ILocalCredentialManager,
	registryMgr commonif.IRegistryManager,
	bootstrapEnsurer BootstrapReadyEnsurer,
	instance *commonmodel.ServiceInstance,
	registryTTLSeconds int64,
) *CredentialDiscoverySupervisorService {
	return &CredentialDiscoverySupervisorService{
		runtime:            runtime,
		startupParams:      startupParams,
		localCredentialMgr: localCredentialMgr,
		registryMgr:        registryMgr,
		bootstrapEnsurer:   bootstrapEnsurer,
		refreshFactory: func(endpoint string) TokenRefreshClient {
			return rpcclient.NewTokenRefreshRPCClient(endpoint)
		},
		instance:           instance,
		registryTTLSeconds: registryTTLSeconds,
		interval:           15 * time.Second,
	}
}

// SetTokenRefreshClientFactory 允许在测试或特殊装配场景下替换 refresh 客户端。
func (s *CredentialDiscoverySupervisorService) SetTokenRefreshClientFactory(factory func(endpoint string) TokenRefreshClient) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if factory == nil {
		s.refreshFactory = func(endpoint string) TokenRefreshClient {
			return rpcclient.NewTokenRefreshRPCClient(endpoint)
		}
		return
	}
	s.refreshFactory = factory
}

// MarkRegistered 标记当前实例已处于服务发现中。
func (s *CredentialDiscoverySupervisorService) MarkRegistered() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.registered = true
	s.mu.Unlock()
}

// MarkUnregistered 标记当前实例已退出服务发现。
func (s *CredentialDiscoverySupervisorService) MarkUnregistered() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.registered = false
	s.mu.Unlock()
}

// Run 启动周期性检查循环。
func (s *CredentialDiscoverySupervisorService) Run(ctx context.Context) {
	if s == nil {
		return
	}
	if err := s.SyncOnce(ctx); err != nil {
		log.Printf("credential discovery sync failed: %v", err)
	}

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.SyncOnce(ctx); err != nil {
				log.Printf("credential discovery sync failed: %v", err)
			}
		}
	}
}

// SyncOnce 执行一次凭证检查与注册/重建动作。
func (s *CredentialDiscoverySupervisorService) SyncOnce(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if s.runtime.RunMode == modelsystem.RuntimeRunModeNoAuth {
		return nil
	}
	if s.localCredentialMgr == nil || s.registryMgr == nil || s.bootstrapEnsurer == nil || s.instance == nil {
		return &modelsystem.ErrModuleCredentialDependenciesRequired
	}

	principalID := s.principalID()
	snapshot, err := s.localCredentialMgr.LoadActiveCredential(ctx, principalID)
	if err != nil {
		return err
	}
	now := time.Now()
	registered := s.isRegistered()
	validForDiscovery := commonsvc.IsCredentialValidForDiscovery(snapshot, now)
	refreshDue := s.shouldRefreshCredential(snapshot, now)
	log.Printf(
		"stage=credential_probe service=%s principal=%s has_snapshot=%t valid_for_discovery=%t refresh_due=%t registered=%t",
		s.runtime.ServiceName,
		principalID,
		snapshot != nil,
		validForDiscovery,
		refreshDue,
		registered,
	)

	if snapshot == nil {
		if registered {
			log.Printf("stage=credential_invalid_unregister service=%s principal=%s reason=missing_snapshot", s.runtime.ServiceName, principalID)
			if err := s.registryMgr.UnRegister(s.instance); err != nil {
				return fmt.Errorf("unregister missing credential instance failed: %w", err)
			}
			s.MarkUnregistered()
		}
		return s.rebootstrapAndRegister(ctx, "missing_snapshot")
	}

	if refreshDue {
		log.Printf(
			"stage=credential_refresh_attempt service=%s principal=%s endpoint=%s",
			s.runtime.ServiceName,
			principalID,
			s.refreshAuthorityEndpoint(snapshot),
		)
		refreshed, refreshErr := s.tryRefreshCredential(ctx, snapshot)
		if refreshErr == nil {
			if persistErr := s.persistRefreshedCredential(ctx, refreshed); persistErr != nil {
				log.Printf("stage=credential_refresh_fail service=%s principal=%s reason=persist error=%v", s.runtime.ServiceName, principalID, persistErr)
				return s.rebootstrapAndRegister(ctx, "refresh_persist_failed")
			}
			log.Printf(
				"stage=credential_refresh_success service=%s principal=%s refresh_expires_at_ms=%s",
				s.runtime.ServiceName,
				principalID,
				refreshed.Metadata["refresh_expires_at_ms"],
			)
			return nil
		}
		log.Printf("stage=credential_refresh_fail service=%s principal=%s reason=rpc error=%v", s.runtime.ServiceName, principalID, refreshErr)
		if !validForDiscovery && registered {
			log.Printf("stage=credential_invalid_unregister service=%s principal=%s reason=refresh_failed", s.runtime.ServiceName, principalID)
			if err := s.registryMgr.UnRegister(s.instance); err != nil {
				return fmt.Errorf("unregister expired credential instance failed: %w", err)
			}
			s.MarkUnregistered()
		}
		return s.rebootstrapAndRegister(ctx, "refresh_failed")
	}

	if !validForDiscovery {
		if registered {
			log.Printf("stage=credential_invalid_unregister service=%s principal=%s reason=invalid_snapshot", s.runtime.ServiceName, principalID)
			if err := s.registryMgr.UnRegister(s.instance); err != nil {
				return fmt.Errorf("unregister expired credential instance failed: %w", err)
			}
			s.MarkUnregistered()
		}
		return s.rebootstrapAndRegister(ctx, "invalid_snapshot")
	}

	return s.ensureRegistered()
}

func (s *CredentialDiscoverySupervisorService) ensureRegistered() error {
	if s.isRegistered() {
		return nil
	}
	if err := s.registryMgr.Register(s.instance, s.registryTTLSeconds); err != nil {
		return err
	}
	s.MarkRegistered()
	return nil
}

func (s *CredentialDiscoverySupervisorService) rebootstrapAndRegister(ctx context.Context, reason string) error {
	principalID := s.principalID()
	log.Printf("stage=credential_rebootstrap_attempt service=%s principal=%s reason=%s", s.runtime.ServiceName, principalID, reason)
	if s.bootstrapEnsurer == nil {
		log.Printf("stage=credential_rebootstrap_fail service=%s principal=%s reason=%s error=%v", s.runtime.ServiceName, principalID, reason, &modelsystem.ErrModuleCredentialDependenciesRequired)
		return &modelsystem.ErrModuleCredentialDependenciesRequired
	}
	if _, err := s.bootstrapEnsurer.EnsureReady(
		ctx,
		&BootstrapStartupRequest{
			Runtime:              s.runtime,
			StartupParams:        s.startupParams,
			AuthAuthorityService: defaultBootstrapAuthorityServiceName,
		},
	); err != nil {
		log.Printf("stage=credential_rebootstrap_fail service=%s principal=%s reason=%s error=%v", s.runtime.ServiceName, principalID, reason, err)
		return err
	}

	snapshot, err := s.localCredentialMgr.LoadActiveCredential(ctx, s.principalID())
	if err != nil {
		log.Printf("stage=credential_rebootstrap_fail service=%s principal=%s reason=%s error=%v", s.runtime.ServiceName, principalID, reason, err)
		return err
	}
	if !commonsvc.IsCredentialValidForDiscovery(snapshot, time.Now()) {
		err = fmt.Errorf("bootstrap credential is not valid for discovery")
		log.Printf("stage=credential_rebootstrap_fail service=%s principal=%s reason=%s error=%v", s.runtime.ServiceName, principalID, reason, err)
		return err
	}

	if err := s.ensureRegistered(); err != nil {
		log.Printf("stage=credential_rebootstrap_fail service=%s principal=%s reason=%s error=%v", s.runtime.ServiceName, principalID, reason, err)
		return err
	}
	log.Printf("stage=credential_rebootstrap_success service=%s principal=%s reason=%s", s.runtime.ServiceName, principalID, reason)
	return nil
}

func (s *CredentialDiscoverySupervisorService) persistRefreshedCredential(ctx context.Context, refreshed *commonif.ModuleCredentialSnapshot) error {
	if refreshed == nil {
		return fmt.Errorf("refreshed credential snapshot is nil")
	}
	if s.localCredentialMgr == nil {
		return &modelsystem.ErrModuleCredentialDependenciesRequired
	}
	if _, err := s.localCredentialMgr.SaveBootstrapCredential(ctx, refreshed); err != nil {
		return fmt.Errorf("save refreshed credential failed: %w", err)
	}
	return s.ensureRegistered()
}

func (s *CredentialDiscoverySupervisorService) tryRefreshCredential(ctx context.Context, snapshot *commonif.ModuleCredentialSnapshot) (*commonif.ModuleCredentialSnapshot, error) {
	if snapshot == nil {
		return nil, fmt.Errorf("credential snapshot is nil")
	}
	endpoint := strings.TrimSpace(snapshot.Metadata["auth_authority_ep"])
	if endpoint == "" {
		return nil, fmt.Errorf("auth authority endpoint is missing from credential snapshot")
	}
	factory := s.refreshFactory
	if factory == nil {
		return nil, fmt.Errorf("token refresh client factory is missing")
	}
	client := factory(endpoint)
	if client == nil {
		return nil, fmt.Errorf("token refresh client is nil")
	}

	now := time.Now()
	refreshReq := &authif.TokenRefreshRequest{
		RefreshToken: strings.TrimSpace(snapshot.RefreshTokenRaw),
		ClientID:     firstNonEmpty(strings.TrimSpace(s.runtime.ServiceName), strings.TrimSpace(snapshot.EntityID)),
		GatewayID:    firstNonEmpty(strings.TrimSpace(s.runtime.InstanceID), strings.TrimSpace(s.runtime.ServiceName)),
		RequestID:    uuid.New().String(),
		TraceID:      uuid.New().String(),
	}
	bundle, err := client.RefreshTokenBundle(ctx, refreshReq)
	if err != nil {
		return nil, err
	}
	return buildRefreshedCredentialSnapshot(snapshot, bundle, now)
}

func (s *CredentialDiscoverySupervisorService) refreshAuthorityEndpoint(snapshot *commonif.ModuleCredentialSnapshot) string {
	if snapshot == nil {
		return ""
	}
	return strings.TrimSpace(snapshot.Metadata["auth_authority_ep"])
}

func buildRefreshedCredentialSnapshot(
	snapshot *commonif.ModuleCredentialSnapshot,
	bundle *authmodel.TokenBundle,
	now time.Time,
) (*commonif.ModuleCredentialSnapshot, error) {
	if snapshot == nil {
		return nil, fmt.Errorf("credential snapshot is nil")
	}
	if bundle == nil || bundle.RefreshToken == nil {
		return nil, fmt.Errorf("refresh token bundle is incomplete")
	}
	refreshToken := bundle.RefreshToken
	if strings.TrimSpace(refreshToken.Raw) == "" {
		return nil, fmt.Errorf("refresh token is missing from refresh response")
	}

	refreshed := cloneCredentialSnapshot(snapshot)
	if refreshed.Metadata == nil {
		refreshed.Metadata = make(map[string]string)
	}
	if bundle.AccessToken != nil && strings.TrimSpace(bundle.AccessToken.Raw) != "" {
		refreshed.AccessTokenRaw = strings.TrimSpace(bundle.AccessToken.Raw)
	}
	refreshed.RefreshTokenRaw = strings.TrimSpace(refreshToken.Raw)
	if refreshToken.Claims.SessionID != uuid.Nil {
		refreshed.SessionID = refreshToken.Claims.SessionID
	}
	if refreshToken.Claims.FamilyID != uuid.Nil {
		refreshed.TokenFamilyID = refreshToken.Claims.FamilyID
	}
	if len(refreshToken.Claims.Scopes) > 0 {
		refreshed.Scopes = append([]string(nil), refreshToken.Claims.Scopes...)
	}
	if role := strings.TrimSpace(refreshToken.Claims.Role); role != "" {
		refreshed.Role = role
	}
	issuedAt := refreshToken.Claims.IssuedAt
	if issuedAt.IsZero() && bundle.AccessToken != nil {
		issuedAt = bundle.AccessToken.Claims.IssuedAt
	}
	if issuedAt.IsZero() {
		issuedAt = now
	}
	expiresAt := refreshToken.Claims.ExpiresAt
	if expiresAt.IsZero() && bundle.AccessToken != nil {
		expiresAt = bundle.AccessToken.Claims.ExpiresAt
	}
	if expiresAt.IsZero() {
		expiresAt = now.Add(24 * time.Hour)
	}
	refreshed.Stage = authmodel.BootstrapStageReady
	refreshed.IssuedAt = issuedAt
	refreshed.ExpiresAt = expiresAt
	refreshed.UpdatedAt = now
	refreshed.Metadata["credential_status"] = "active"
	refreshed.Metadata["last_refresh_at_ms"] = strconv.FormatInt(now.UnixMilli(), 10)
	refreshed.Metadata["refresh_expires_at_ms"] = strconv.FormatInt(expiresAt.UnixMilli(), 10)
	delete(refreshed.Metadata, "next_refresh_at_ms")
	refreshed.Metadata["next_refresh_at_ms"] = strconv.FormatInt(resolveNextRefreshAt(refreshed, now).UnixMilli(), 10)
	return refreshed, nil
}

func (s *CredentialDiscoverySupervisorService) shouldRefreshCredential(snapshot *commonif.ModuleCredentialSnapshot, now time.Time) bool {
	if snapshot == nil || strings.TrimSpace(snapshot.RefreshTokenRaw) == "" {
		return false
	}
	if !commonsvc.IsCredentialValidForDiscovery(snapshot, now) {
		return true
	}
	nextRefreshAt := resolveNextRefreshAt(snapshot, now)
	if nextRefreshAt.IsZero() {
		return false
	}
	return !nextRefreshAt.After(now)
}

func resolveNextRefreshAt(snapshot *commonif.ModuleCredentialSnapshot, now time.Time) time.Time {
	if snapshot == nil {
		return time.Time{}
	}
	if raw := strings.TrimSpace(snapshot.Metadata["next_refresh_at_ms"]); raw != "" {
		if millis, err := strconv.ParseInt(raw, 10, 64); err == nil && millis > 0 {
			candidate := time.UnixMilli(millis)
			if !candidate.IsZero() {
				return candidate
			}
		}
	}
	if snapshot.ExpiresAt.IsZero() {
		return time.Time{}
	}
	candidate := snapshot.ExpiresAt.Add(-5 * time.Minute)
	if candidate.After(now) {
		return candidate
	}
	return now
}

func cloneCredentialSnapshot(snapshot *commonif.ModuleCredentialSnapshot) *commonif.ModuleCredentialSnapshot {
	if snapshot == nil {
		return nil
	}
	clone := *snapshot
	if snapshot.Scopes != nil {
		clone.Scopes = append([]string(nil), snapshot.Scopes...)
	}
	if snapshot.Metadata != nil {
		clone.Metadata = make(map[string]string, len(snapshot.Metadata))
		for key, value := range snapshot.Metadata {
			clone.Metadata[key] = value
		}
	}
	return &clone
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func (s *CredentialDiscoverySupervisorService) isRegistered() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.registered
}

func (s *CredentialDiscoverySupervisorService) principalID() string {
	entityType := normalizeBootstrapEntityType(s.runtime.EntityType)
	entityID := strings.TrimSpace(s.runtime.InstanceID)
	if entityID == "" {
		entityID = strings.TrimSpace(s.runtime.ServiceName)
	}
	return fmt.Sprintf("%s:%s", entityType, entityID)
}
