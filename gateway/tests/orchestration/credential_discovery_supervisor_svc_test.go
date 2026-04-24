package orchestration

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	commonif "gateway/src/iface/common"
	authmodel "gateway/src/models/auth"
	commonmodel "gateway/src/models/common"
	modelsystem "gateway/src/models/system"
	commonsvc "gateway/src/services/common"
	orchestration "gateway/src/services/orchestration"

	"github.com/google/uuid"
)

type memoryCredentialManager struct {
	snapshots map[string]*commonif.ModuleCredentialSnapshot
}

func (m *memoryCredentialManager) SaveBootstrapCredential(ctx context.Context, snapshot *commonif.ModuleCredentialSnapshot) (string, error) {
	_ = ctx
	if m.snapshots == nil {
		m.snapshots = make(map[string]*commonif.ModuleCredentialSnapshot)
	}
	clone := cloneCredentialSnapshot(snapshot)
	m.snapshots[clone.PrincipalID] = clone
	return "/memory/" + clone.PrincipalID, nil
}

func (m *memoryCredentialManager) LoadActiveCredential(ctx context.Context, principalID string) (*commonif.ModuleCredentialSnapshot, error) {
	_ = ctx
	if m.snapshots == nil {
		return nil, nil
	}
	snapshot, ok := m.snapshots[strings.TrimSpace(principalID)]
	if !ok || snapshot == nil {
		return nil, nil
	}
	return cloneCredentialSnapshot(snapshot), nil
}

func (m *memoryCredentialManager) MarkCredentialExpired(ctx context.Context, principalID string, reason string) error {
	_ = ctx
	_ = reason
	snapshot, ok := m.snapshots[strings.TrimSpace(principalID)]
	if !ok || snapshot == nil {
		return nil
	}
	snapshot.Stage = authmodel.BootstrapStageUninitialized
	if snapshot.Metadata == nil {
		snapshot.Metadata = make(map[string]string)
	}
	snapshot.Metadata["credential_status"] = "expired"
	return nil
}

func (m *memoryCredentialManager) RevokeCredential(ctx context.Context, principalID string, reason string) error {
	_ = ctx
	_ = reason
	delete(m.snapshots, strings.TrimSpace(principalID))
	return nil
}

type recordingRegistryManager struct {
	registerCalls   int
	unregisterCalls int
	lastTTL         int64
	lastInstance    *commonmodel.ServiceInstance
}

func (r *recordingRegistryManager) Register(instance *commonmodel.ServiceInstance, ttl int64) error {
	r.registerCalls++
	r.lastTTL = ttl
	r.lastInstance = instance
	return nil
}

func (r *recordingRegistryManager) UnRegister(instance *commonmodel.ServiceInstance) error {
	r.unregisterCalls++
	r.lastInstance = instance
	return nil
}

func (r *recordingRegistryManager) GetServiceInstances(serviceName string) ([]*commonmodel.ServiceInstance, error) {
	_ = serviceName
	return nil, nil
}

func (r *recordingRegistryManager) GetServiceSnapShot(serviceName string) (*commonmodel.ServiceSnapshot, error) {
	_ = serviceName
	return nil, nil
}

func (r *recordingRegistryManager) ChooseEndpoint(serviceName string, affinityKey string, requireTags []string) (*commonmodel.ServiceInstance, error) {
	_ = serviceName
	_ = affinityKey
	_ = requireTags
	return nil, nil
}

type bootstrapCoordinatorStub struct {
	credentialMgr    *memoryCredentialManager
	ensureSnapshot   *commonif.ModuleCredentialSnapshot
	refreshSnapshot  *commonif.ModuleCredentialSnapshot
	ensureCallCount  int
	refreshCallCount int
	revokeCallCount  int
	revokeReason     string
}

func (b *bootstrapCoordinatorStub) EnsureModuleReady(ctx context.Context) (*commonif.ModuleCredentialSnapshot, error) {
	_ = ctx
	b.ensureCallCount++
	if b.ensureSnapshot == nil {
		return nil, nil
	}
	clone := cloneCredentialSnapshot(b.ensureSnapshot)
	if b.credentialMgr != nil {
		if b.credentialMgr.snapshots == nil {
			b.credentialMgr.snapshots = make(map[string]*commonif.ModuleCredentialSnapshot)
		}
		b.credentialMgr.snapshots[clone.PrincipalID] = cloneCredentialSnapshot(clone)
	}
	return clone, nil
}

func (b *bootstrapCoordinatorStub) RefreshModuleCredential(ctx context.Context) (*commonif.ModuleCredentialSnapshot, error) {
	_ = ctx
	b.refreshCallCount++
	if b.refreshSnapshot == nil {
		return nil, nil
	}
	clone := cloneCredentialSnapshot(b.refreshSnapshot)
	if b.credentialMgr != nil {
		if b.credentialMgr.snapshots == nil {
			b.credentialMgr.snapshots = make(map[string]*commonif.ModuleCredentialSnapshot)
		}
		b.credentialMgr.snapshots[clone.PrincipalID] = cloneCredentialSnapshot(clone)
	}
	return clone, nil
}

func (b *bootstrapCoordinatorStub) RevokeModuleCredential(ctx context.Context, reason string) error {
	_ = ctx
	b.revokeCallCount++
	b.revokeReason = reason
	return nil
}

func buildCredentialSnapshot(
	principalID string,
	runtime modelsystem.RuntimeConfig,
	sessionID uuid.UUID,
	familyID uuid.UUID,
	accessToken string,
	refreshToken string,
	activeCommKeyID string,
	issuedAt time.Time,
	expiresAt time.Time,
	updatedAt time.Time,
	nextRefreshAt time.Time,
	authAuthorityEndpoint string,
) *commonif.ModuleCredentialSnapshot {
	return &commonif.ModuleCredentialSnapshot{
		PrincipalID:     principalID,
		EntityType:      commonmodel.EntityType(runtime.EntityType),
		EntityID:        runtime.InstanceID,
		SessionID:       sessionID,
		TokenFamilyID:   familyID,
		AccessTokenRaw:  accessToken,
		RefreshTokenRaw: refreshToken,
		Scopes:          []string{"gateway:discover"},
		Role:            "service",
		Stage:           authmodel.BootstrapStageReady,
		ActiveCommKeyID: activeCommKeyID,
		IssuedAt:        issuedAt,
		ExpiresAt:       expiresAt,
		UpdatedAt:       updatedAt,
		Metadata: map[string]string{
			"credential_status":     "active",
			"auth_authority_ep":     authAuthorityEndpoint,
			"next_refresh_at_ms":    strconv.FormatInt(nextRefreshAt.UnixMilli(), 10),
			"refresh_expires_at_ms": strconv.FormatInt(expiresAt.UnixMilli(), 10),
		},
	}
}

func TestCredentialDiscoverySupervisorSyncOnceRebuildsExpiredCredentialAndRegisters(t *testing.T) {
	runtime := modelsystem.RuntimeConfig{
		EntityType:  "service",
		ServiceName: "gateway",
		InstanceID:  "gateway-instance",
		RunMode:     modelsystem.RuntimeRunModeDevelopment,
	}
	principalID := "service:gateway-instance"
	now := time.Now().UTC()
	expiredSnapshot := buildCredentialSnapshot(
		principalID,
		runtime,
		uuid.MustParse("44444444-4444-4444-4444-444444444444"),
		uuid.MustParse("55555555-5555-5555-5555-555555555555"),
		"access-old",
		"",
		"gateway-local-key",
		now.Add(-2*time.Hour),
		now.Add(-time.Minute),
		now.Add(-time.Minute),
		now.Add(-time.Minute),
		"certification_server:9000",
	)
	bootstrapSnapshot := buildCredentialSnapshot(
		principalID,
		runtime,
		uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		uuid.MustParse("33333333-3333-3333-3333-333333333333"),
		"access-token",
		"refresh-token",
		"gateway-local-key",
		now,
		now.Add(2*time.Hour),
		now,
		now.Add(30*time.Minute),
		"certification_server:9000",
	)

	credentialMgr := &memoryCredentialManager{
		snapshots: map[string]*commonif.ModuleCredentialSnapshot{
			principalID: expiredSnapshot,
		},
	}
	registryMgr := &recordingRegistryManager{}
	bootstrapCoordinator := &bootstrapCoordinatorStub{
		credentialMgr:  credentialMgr,
		ensureSnapshot: bootstrapSnapshot,
	}
	instance := &commonmodel.ServiceInstance{
		ID:        uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		Name:      runtime.ServiceName,
		Endpoint:  "127.0.0.1:8080",
		HeartBeat: now.UnixMilli(),
		Weight:    1,
	}

	supervisor := orchestration.NewCredentialDiscoverySupervisorService(
		runtime,
		credentialMgr,
		registryMgr,
		bootstrapCoordinator,
		instance,
		30,
	)
	supervisor.MarkRegistered()

	if err := supervisor.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce returned error: %v", err)
	}
	if bootstrapCoordinator.ensureCallCount != 1 {
		t.Fatalf("bootstrap call count = %d, want %d", bootstrapCoordinator.ensureCallCount, 1)
	}
	if registryMgr.unregisterCalls != 1 {
		t.Fatalf("unregister call count = %d, want %d", registryMgr.unregisterCalls, 1)
	}
	if registryMgr.registerCalls != 1 {
		t.Fatalf("register call count = %d, want %d", registryMgr.registerCalls, 1)
	}
	if registryMgr.lastTTL != 30 {
		t.Fatalf("register ttl = %d, want %d", registryMgr.lastTTL, 30)
	}

	snapshot, err := credentialMgr.LoadActiveCredential(context.Background(), principalID)
	if err != nil {
		t.Fatalf("LoadActiveCredential returned error: %v", err)
	}
	if !commonsvc.IsCredentialValidForDiscovery(snapshot, time.Now()) {
		t.Fatal("expected re-bootstrap credential to be valid for discovery")
	}
}

func TestCredentialDiscoverySupervisorSyncOnceRefreshesBeforeRebootstrap(t *testing.T) {
	runtime := modelsystem.RuntimeConfig{
		EntityType:  "service",
		ServiceName: "gateway",
		InstanceID:  "gateway-instance",
		RunMode:     modelsystem.RuntimeRunModeDevelopment,
	}
	now := time.Now().UTC()
	principalID := "service:gateway-instance"
	initialSnapshot := buildCredentialSnapshot(
		principalID,
		runtime,
		uuid.MustParse("44444444-4444-4444-4444-444444444444"),
		uuid.MustParse("55555555-5555-5555-5555-555555555555"),
		"access-old",
		"refresh-old",
		"gateway-local-key",
		now.Add(-20*time.Minute),
		now.Add(2*time.Hour),
		now.Add(-20*time.Minute),
		now.Add(-time.Minute),
		"certification_server:9000",
	)
	refreshedSnapshot := buildCredentialSnapshot(
		principalID,
		runtime,
		initialSnapshot.SessionID,
		initialSnapshot.TokenFamilyID,
		"access-new",
		"refresh-new",
		"gateway-local-key",
		now,
		now.Add(24*time.Hour),
		now,
		now.Add(30*time.Minute),
		"certification_server:9000",
	)

	credentialMgr := &memoryCredentialManager{
		snapshots: map[string]*commonif.ModuleCredentialSnapshot{
			principalID: initialSnapshot,
		},
	}
	registryMgr := &recordingRegistryManager{}
	bootstrapCoordinator := &bootstrapCoordinatorStub{
		credentialMgr:   credentialMgr,
		refreshSnapshot: refreshedSnapshot,
	}
	instance := &commonmodel.ServiceInstance{
		ID:        uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		Name:      runtime.ServiceName,
		Endpoint:  "127.0.0.1:8080",
		HeartBeat: now.UnixMilli(),
		Weight:    1,
	}

	supervisor := orchestration.NewCredentialDiscoverySupervisorService(
		runtime,
		credentialMgr,
		registryMgr,
		bootstrapCoordinator,
		instance,
		30,
	)
	supervisor.MarkRegistered()

	if err := supervisor.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce returned error: %v", err)
	}
	if bootstrapCoordinator.refreshCallCount != 1 {
		t.Fatalf("refresh call count = %d, want %d", bootstrapCoordinator.refreshCallCount, 1)
	}
	if bootstrapCoordinator.ensureCallCount != 0 {
		t.Fatalf("bootstrap call count = %d, want %d", bootstrapCoordinator.ensureCallCount, 0)
	}
	if registryMgr.unregisterCalls != 0 {
		t.Fatalf("unregister call count = %d, want %d", registryMgr.unregisterCalls, 0)
	}
	if registryMgr.registerCalls != 0 {
		t.Fatalf("register call count = %d, want %d", registryMgr.registerCalls, 0)
	}

	snapshot, err := credentialMgr.LoadActiveCredential(context.Background(), principalID)
	if err != nil {
		t.Fatalf("LoadActiveCredential returned error: %v", err)
	}
	if snapshot.RefreshTokenRaw != "refresh-new" {
		t.Fatalf("refresh token = %q, want %q", snapshot.RefreshTokenRaw, "refresh-new")
	}
	if snapshot.AccessTokenRaw != "access-new" {
		t.Fatalf("access token = %q, want %q", snapshot.AccessTokenRaw, "access-new")
	}
	nextRefreshAtMs, err := strconv.ParseInt(snapshot.Metadata["next_refresh_at_ms"], 10, 64)
	if err != nil {
		t.Fatalf("parse next_refresh_at_ms: %v", err)
	}
	refreshExpiresAtMs, err := strconv.ParseInt(snapshot.Metadata["refresh_expires_at_ms"], 10, 64)
	if err != nil {
		t.Fatalf("parse refresh_expires_at_ms: %v", err)
	}
	if nextRefreshAtMs <= time.Now().UnixMilli() {
		t.Fatalf("next_refresh_at_ms = %d, want future timestamp", nextRefreshAtMs)
	}
	if nextRefreshAtMs >= refreshExpiresAtMs {
		t.Fatalf("next_refresh_at_ms = %d, want before refresh expiry %d", nextRefreshAtMs, refreshExpiresAtMs)
	}
	if !commonsvc.IsCredentialValidForDiscovery(snapshot, time.Now()) {
		t.Fatal("expected refreshed credential to remain valid for discovery")
	}
}

func TestCredentialDiscoverySupervisorSyncOnceUnregistersMissingSnapshotBeforeRebootstrap(t *testing.T) {
	runtime := modelsystem.RuntimeConfig{
		EntityType:  "service",
		ServiceName: "gateway",
		InstanceID:  "gateway-instance",
		RunMode:     modelsystem.RuntimeRunModeDevelopment,
	}
	principalID := "service:gateway-instance"
	now := time.Now().UTC()
	credentialMgr := &memoryCredentialManager{snapshots: map[string]*commonif.ModuleCredentialSnapshot{}}
	registryMgr := &recordingRegistryManager{}
	bootstrapCoordinator := &bootstrapCoordinatorStub{
		credentialMgr: credentialMgr,
		ensureSnapshot: buildCredentialSnapshot(
			principalID,
			runtime,
			uuid.MustParse("22222222-2222-2222-2222-222222222222"),
			uuid.MustParse("33333333-3333-3333-3333-333333333333"),
			"access-token",
			"refresh-token",
			"gateway-local-key",
			now,
			now.Add(2*time.Hour),
			now,
			now.Add(30*time.Minute),
			"certification_server:9000",
		),
	}
	instance := &commonmodel.ServiceInstance{
		ID:        uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		Name:      runtime.ServiceName,
		Endpoint:  "127.0.0.1:8080",
		HeartBeat: now.UnixMilli(),
		Weight:    1,
	}

	supervisor := orchestration.NewCredentialDiscoverySupervisorService(
		runtime,
		credentialMgr,
		registryMgr,
		bootstrapCoordinator,
		instance,
		30,
	)
	supervisor.MarkRegistered()

	if err := supervisor.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce returned error: %v", err)
	}
	if bootstrapCoordinator.ensureCallCount != 1 {
		t.Fatalf("bootstrap call count = %d, want %d", bootstrapCoordinator.ensureCallCount, 1)
	}
	if registryMgr.unregisterCalls != 1 {
		t.Fatalf("unregister call count = %d, want %d", registryMgr.unregisterCalls, 1)
	}
	if registryMgr.registerCalls != 1 {
		t.Fatalf("register call count = %d, want %d", registryMgr.registerCalls, 1)
	}

	snapshot, err := credentialMgr.LoadActiveCredential(context.Background(), principalID)
	if err != nil {
		t.Fatalf("LoadActiveCredential returned error: %v", err)
	}
	if !commonsvc.IsCredentialValidForDiscovery(snapshot, time.Now()) {
		t.Fatal("expected re-bootstrap credential to be valid for discovery")
	}
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
