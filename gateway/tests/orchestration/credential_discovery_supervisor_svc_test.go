package orchestration

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	authif "gateway/src/iface/auth"
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

type bootstrapEnsurerStub struct {
	credentialMgr *memoryCredentialManager
	callCount     int
}

func (b *bootstrapEnsurerStub) EnsureReady(ctx context.Context, req *orchestration.BootstrapStartupRequest) (*orchestration.BootstrapStartupResult, error) {
	_ = ctx
	b.callCount++
	principalID := strings.ToLower(strings.TrimSpace(req.Runtime.EntityType)) + ":" + strings.TrimSpace(req.Runtime.InstanceID)
	now := time.Now().UTC()
	expiresAt := now.Add(2 * time.Hour)
	if b.credentialMgr.snapshots == nil {
		b.credentialMgr.snapshots = make(map[string]*commonif.ModuleCredentialSnapshot)
	}
	b.credentialMgr.snapshots[principalID] = &commonif.ModuleCredentialSnapshot{
		PrincipalID:     principalID,
		EntityType:      commonmodel.EntityType(req.Runtime.EntityType),
		EntityID:        req.Runtime.InstanceID,
		SessionID:       uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		TokenFamilyID:   uuid.MustParse("33333333-3333-3333-3333-333333333333"),
		AccessTokenRaw:  "access-token",
		RefreshTokenRaw: "refresh-token",
		Scopes:          []string{"gateway:discover"},
		Role:            "service",
		Stage:           authmodel.BootstrapStageReady,
		ActiveCommKeyID: "gateway-local-key",
		IssuedAt:        now,
		ExpiresAt:       expiresAt,
		UpdatedAt:       now,
		Metadata: map[string]string{
			"credential_status":     "active",
			"auth_authority_ep":     "certification_server:9000",
			"next_refresh_at_ms":    strconv.FormatInt(now.Add(30*time.Minute).UnixMilli(), 10),
			"refresh_expires_at_ms": strconv.FormatInt(expiresAt.UnixMilli(), 10),
		},
	}
	return &orchestration.BootstrapStartupResult{
		Stage:             string(authmodel.BootstrapStageReady),
		AuthorityEndpoint: "certification_server:9000",
		CredentialKey:     "/memory/" + principalID,
	}, nil
}

func TestCredentialDiscoverySupervisorSyncOnceRebuildsExpiredCredentialAndRegisters(t *testing.T) {
	runtime := modelsystem.RuntimeConfig{
		EntityType:  "service",
		ServiceName: "gateway",
		InstanceID:  "gateway-instance",
		RunMode:     modelsystem.RuntimeRunModeDevelopment,
	}
	startupParams := modelsystem.SecretKeyStartupParams{
		ActiveKeyID:  "gateway-local-key",
		EntityType:   runtime.EntityType,
		EntityID:     runtime.InstanceID,
		EntityName:   runtime.ServiceName,
		InstanceID:   runtime.InstanceID,
		InstanceName: runtime.ServiceName,
	}
	principalID := "service:gateway-instance"
	expiredSnapshot := &commonif.ModuleCredentialSnapshot{
		PrincipalID:     principalID,
		EntityType:      commonmodel.EntityType(runtime.EntityType),
		EntityID:        runtime.InstanceID,
		RefreshTokenRaw: "",
		Stage:           authmodel.BootstrapStageReady,
		ActiveCommKeyID: "gateway-local-key",
		IssuedAt:        time.Now().Add(-2 * time.Hour),
		ExpiresAt:       time.Now().Add(-time.Minute),
		UpdatedAt:       time.Now().Add(-time.Minute),
		Metadata: map[string]string{
			"credential_status":     "expired",
			"refresh_expires_at_ms": strconv.FormatInt(time.Now().Add(-time.Minute).UnixMilli(), 10),
		},
	}

	credentialMgr := &memoryCredentialManager{
		snapshots: map[string]*commonif.ModuleCredentialSnapshot{
			principalID: expiredSnapshot,
		},
	}
	registryMgr := &recordingRegistryManager{}
	bootstrapEnsurer := &bootstrapEnsurerStub{credentialMgr: credentialMgr}
	instance := &commonmodel.ServiceInstance{
		ID:        uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		Name:      runtime.ServiceName,
		Endpoint:  "127.0.0.1:8080",
		HeartBeat: time.Now().UnixMilli(),
		Weight:    1,
	}

	supervisor := orchestration.NewCredentialDiscoverySupervisorService(
		runtime,
		startupParams,
		credentialMgr,
		registryMgr,
		bootstrapEnsurer,
		instance,
		30,
	)
	supervisor.MarkRegistered()

	if err := supervisor.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce returned error: %v", err)
	}
	if bootstrapEnsurer.callCount != 1 {
		t.Fatalf("bootstrap call count = %d, want %d", bootstrapEnsurer.callCount, 1)
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

type stubTokenRefreshClient struct {
	callCount int
	response  *authmodel.TokenBundle
}

func (s *stubTokenRefreshClient) RefreshTokenBundle(ctx context.Context, req *authif.TokenRefreshRequest) (*authmodel.TokenBundle, error) {
	_ = ctx
	_ = req
	s.callCount++
	return s.response, nil
}

func TestCredentialDiscoverySupervisorSyncOnceRefreshesBeforeRebootstrap(t *testing.T) {
	runtime := modelsystem.RuntimeConfig{
		EntityType:  "service",
		ServiceName: "gateway",
		InstanceID:  "gateway-instance",
		RunMode:     modelsystem.RuntimeRunModeDevelopment,
	}
	startupParams := modelsystem.SecretKeyStartupParams{
		ActiveKeyID:  "gateway-local-key",
		EntityType:   runtime.EntityType,
		EntityID:     runtime.InstanceID,
		EntityName:   runtime.ServiceName,
		InstanceID:   runtime.InstanceID,
		InstanceName: runtime.ServiceName,
	}
	now := time.Now().UTC()
	principalID := "service:gateway-instance"
	initialSnapshot := &commonif.ModuleCredentialSnapshot{
		PrincipalID:     principalID,
		EntityType:      commonmodel.EntityType(runtime.EntityType),
		EntityID:        runtime.InstanceID,
		SessionID:       uuid.MustParse("44444444-4444-4444-4444-444444444444"),
		TokenFamilyID:   uuid.MustParse("55555555-5555-5555-5555-555555555555"),
		AccessTokenRaw:  "access-old",
		RefreshTokenRaw: "refresh-old",
		Scopes:          []string{"gateway:discover"},
		Role:            "service",
		Stage:           authmodel.BootstrapStageReady,
		ActiveCommKeyID: "gateway-local-key",
		IssuedAt:        now.Add(-20 * time.Minute),
		ExpiresAt:       now.Add(2 * time.Hour),
		UpdatedAt:       now.Add(-20 * time.Minute),
		Metadata: map[string]string{
			"credential_status":     "active",
			"auth_authority_ep":     "certification_server:9000",
			"next_refresh_at_ms":    strconv.FormatInt(now.Add(-time.Minute).UnixMilli(), 10),
			"refresh_expires_at_ms": strconv.FormatInt(now.Add(2*time.Hour).UnixMilli(), 10),
		},
	}
	credentialMgr := &memoryCredentialManager{
		snapshots: map[string]*commonif.ModuleCredentialSnapshot{
			principalID: initialSnapshot,
		},
	}
	registryMgr := &recordingRegistryManager{}
	refreshClient := &stubTokenRefreshClient{
		response: &authmodel.TokenBundle{
			AccessToken: &authmodel.IssuedToken{
				Raw: "access-new",
				Claims: authmodel.TokenClaims{
					IssuedAt:  now,
					ExpiresAt: now.Add(5 * time.Minute),
				},
			},
			RefreshToken: &authmodel.IssuedToken{
				Raw: "refresh-new",
				Claims: authmodel.TokenClaims{
					SessionID: uuid.MustParse("44444444-4444-4444-4444-444444444444"),
					FamilyID:  uuid.MustParse("55555555-5555-5555-5555-555555555555"),
					IssuedAt:  now,
					ExpiresAt: now.Add(24 * time.Hour),
					Scopes:    []string{"gateway:discover"},
					Role:      "service",
				},
			},
		},
	}
	bootstrapEnsurer := &bootstrapEnsurerStub{credentialMgr: credentialMgr}
	instance := &commonmodel.ServiceInstance{
		ID:        uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		Name:      runtime.ServiceName,
		Endpoint:  "127.0.0.1:8080",
		HeartBeat: now.UnixMilli(),
		Weight:    1,
	}

	supervisor := orchestration.NewCredentialDiscoverySupervisorService(
		runtime,
		startupParams,
		credentialMgr,
		registryMgr,
		bootstrapEnsurer,
		instance,
		30,
	)
	supervisor.SetTokenRefreshClientFactory(func(endpoint string) orchestration.TokenRefreshClient {
		_ = endpoint
		return refreshClient
	})
	supervisor.MarkRegistered()

	if err := supervisor.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce returned error: %v", err)
	}
	if refreshClient.callCount != 1 {
		t.Fatalf("refresh call count = %d, want %d", refreshClient.callCount, 1)
	}
	if bootstrapEnsurer.callCount != 0 {
		t.Fatalf("bootstrap call count = %d, want %d", bootstrapEnsurer.callCount, 0)
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
	startupParams := modelsystem.SecretKeyStartupParams{
		ActiveKeyID:  "gateway-local-key",
		EntityType:   runtime.EntityType,
		EntityID:     runtime.InstanceID,
		EntityName:   runtime.ServiceName,
		InstanceID:   runtime.InstanceID,
		InstanceName: runtime.ServiceName,
	}
	principalID := "service:gateway-instance"
	credentialMgr := &memoryCredentialManager{snapshots: map[string]*commonif.ModuleCredentialSnapshot{}}
	registryMgr := &recordingRegistryManager{}
	bootstrapEnsurer := &bootstrapEnsurerStub{credentialMgr: credentialMgr}
	instance := &commonmodel.ServiceInstance{
		ID:        uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		Name:      runtime.ServiceName,
		Endpoint:  "127.0.0.1:8080",
		HeartBeat: time.Now().UnixMilli(),
		Weight:    1,
	}

	supervisor := orchestration.NewCredentialDiscoverySupervisorService(
		runtime,
		startupParams,
		credentialMgr,
		registryMgr,
		bootstrapEnsurer,
		instance,
		30,
	)
	supervisor.MarkRegistered()

	if err := supervisor.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce returned error: %v", err)
	}
	if bootstrapEnsurer.callCount != 1 {
		t.Fatalf("bootstrap call count = %d, want %d", bootstrapEnsurer.callCount, 1)
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
