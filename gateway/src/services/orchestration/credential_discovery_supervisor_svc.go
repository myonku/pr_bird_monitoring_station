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
	commonmodel "gateway/src/models/common"
	modelsystem "gateway/src/models/system"
	commonsvc "gateway/src/services/common"
)

// CredentialDiscoverySupervisorService 周期性检测本地凭证状态，并控制服务发现参与。
type CredentialDiscoverySupervisorService struct {
	runtime              modelsystem.RuntimeConfig
	localCredentialMgr   commonif.ILocalCredentialManager
	registryMgr          commonif.IRegistryManager
	bootstrapCoordinator authif.IBootstrapCoordinator
	instance             *commonmodel.ServiceInstance
	registryTTLSeconds   int64
	interval             time.Duration

	mu         sync.Mutex
	registered bool
}

// NewCredentialDiscoverySupervisorService 创建凭证驱动的服务发现监督器。
func NewCredentialDiscoverySupervisorService(
	runtime modelsystem.RuntimeConfig,
	localCredentialMgr commonif.ILocalCredentialManager,
	registryMgr commonif.IRegistryManager,
	bootstrapCoordinator authif.IBootstrapCoordinator,
	instance *commonmodel.ServiceInstance,
	registryTTLSeconds int64,
) *CredentialDiscoverySupervisorService {
	return &CredentialDiscoverySupervisorService{
		runtime:              runtime,
		localCredentialMgr:   localCredentialMgr,
		registryMgr:          registryMgr,
		bootstrapCoordinator: bootstrapCoordinator,
		instance:             instance,
		registryTTLSeconds:   registryTTLSeconds,
		interval:             15 * time.Second,
	}
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
	if s.localCredentialMgr == nil || s.registryMgr == nil || s.bootstrapCoordinator == nil || s.instance == nil {
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
		refreshed, refreshErr := s.bootstrapCoordinator.RefreshModuleCredential(ctx)
		if refreshErr == nil {
			log.Printf(
				"stage=credential_refresh_success service=%s principal=%s refresh_expires_at_ms=%s",
				s.runtime.ServiceName,
				principalID,
				refreshed.Metadata["refresh_expires_at_ms"],
			)
			return s.ensureRegistered(refreshed)
		}
		log.Printf("stage=credential_refresh_fail service=%s principal=%s reason=rpc error=%v", s.runtime.ServiceName, principalID, refreshErr)
		if registered {
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

	return s.ensureRegistered(snapshot)
}

func (s *CredentialDiscoverySupervisorService) ensureRegistered(snapshot *commonif.ModuleCredentialSnapshot) error {
	if snapshot == nil {
		return fmt.Errorf("credential snapshot is nil")
	}
	resolvedActiveCommKeyID := strings.TrimSpace(snapshot.ActiveCommKeyID)
	if resolvedActiveCommKeyID == "" {
		resolvedActiveCommKeyID = strings.TrimSpace(s.instance.ActiveCommKeyID)
	}
	if resolvedActiveCommKeyID == "" {
		return fmt.Errorf("active communication key id is missing from snapshot")
	}
	if s.instance != nil {
		s.instance.ActiveCommKeyID = resolvedActiveCommKeyID
	}
	if s.isRegistered() {
		return nil
	}
	if err := s.registryMgr.Register(s.instance, s.registryTTLSeconds); err != nil {
		return err
	}
	s.MarkRegistered()
	return nil
}

func (s *CredentialDiscoverySupervisorService) refreshAuthorityEndpoint(snapshot *commonif.ModuleCredentialSnapshot) string {
	if snapshot == nil {
		return ""
	}
	return strings.TrimSpace(snapshot.Metadata["auth_authority_ep"])
}

func (s *CredentialDiscoverySupervisorService) rebootstrapAndRegister(ctx context.Context, reason string) error {
	principalID := s.principalID()
	log.Printf("stage=credential_rebootstrap_attempt service=%s principal=%s reason=%s", s.runtime.ServiceName, principalID, reason)
	if s.bootstrapCoordinator == nil {
		log.Printf("stage=credential_rebootstrap_fail service=%s principal=%s reason=%s error=%v", s.runtime.ServiceName, principalID, reason, &modelsystem.ErrModuleCredentialDependenciesRequired)
		return &modelsystem.ErrModuleCredentialDependenciesRequired
	}
	snapshot, err := s.bootstrapCoordinator.EnsureModuleReady(ctx)
	if err != nil {
		log.Printf("stage=credential_rebootstrap_fail service=%s principal=%s reason=%s error=%v", s.runtime.ServiceName, principalID, reason, err)
		return err
	}
	if !commonsvc.IsCredentialValidForDiscovery(snapshot, time.Now()) {
		err = fmt.Errorf("bootstrap credential is not valid for discovery")
		log.Printf("stage=credential_rebootstrap_fail service=%s principal=%s reason=%s error=%v", s.runtime.ServiceName, principalID, reason, err)
		return err
	}

	if err := s.ensureRegistered(snapshot); err != nil {
		log.Printf("stage=credential_rebootstrap_fail service=%s principal=%s reason=%s error=%v", s.runtime.ServiceName, principalID, reason, err)
		return err
	}
	log.Printf("stage=credential_rebootstrap_success service=%s principal=%s reason=%s", s.runtime.ServiceName, principalID, reason)
	return nil
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
