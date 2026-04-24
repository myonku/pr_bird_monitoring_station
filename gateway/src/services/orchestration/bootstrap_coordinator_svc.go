package orchestration

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	authif "gateway/src/iface/auth"
	commonif "gateway/src/iface/common"
	authmodel "gateway/src/models/auth"
	modelsystem "gateway/src/models/system"
	commonsvc "gateway/src/services/common"
	rpcclient "gateway/src/services/communication/rpc_client"

	"github.com/google/uuid"
)

type bootstrapReadyExecutor interface {
	EnsureReady(ctx context.Context, req *BootstrapStartupRequest) (*BootstrapStartupResult, error)
}

type tokenRefreshExecutor interface {
	RefreshTokenBundle(ctx context.Context, req *authif.TokenRefreshRequest) (*authmodel.TokenBundle, error)
}

var _ authif.IBootstrapCoordinator = (*BootstrapCoordinatorService)(nil)

// BootstrapCoordinatorService 将启动期 bootstrap、运行期 refresh 和本地凭证持久化
// 收敛到一个模块级协调面，供 supervisor 与生命周期统一依赖。
type BootstrapCoordinatorService struct {
	runtime              modelsystem.RuntimeConfig
	startupParams        modelsystem.SecretKeyStartupParams
	localCredentialMgr   commonif.ILocalCredentialManager
	bootstrapExecutor    bootstrapReadyExecutor
	refreshFactory       func(endpoint string) tokenRefreshExecutor
	authAuthorityService string
}

// NewBootstrapCoordinatorService 创建模块凭证协调器。
func NewBootstrapCoordinatorService(
	runtime modelsystem.RuntimeConfig,
	startupParams modelsystem.SecretKeyStartupParams,
	localCredentialMgr commonif.ILocalCredentialManager,
	bootstrapExecutor bootstrapReadyExecutor,
	refreshFactory func(endpoint string) tokenRefreshExecutor,
	authAuthorityService string,
) *BootstrapCoordinatorService {
	resolvedAuthority := strings.TrimSpace(authAuthorityService)
	if resolvedAuthority == "" {
		resolvedAuthority = defaultBootstrapAuthorityServiceName
	}
	if refreshFactory == nil {
		refreshFactory = func(endpoint string) tokenRefreshExecutor {
			return rpcclient.NewTokenRefreshRPCClient(endpoint)
		}
	}
	return &BootstrapCoordinatorService{
		runtime:              runtime,
		startupParams:        startupParams,
		localCredentialMgr:   localCredentialMgr,
		bootstrapExecutor:    bootstrapExecutor,
		refreshFactory:       refreshFactory,
		authAuthorityService: resolvedAuthority,
	}
}

// EnsureModuleReady 执行启动期 bootstrap，并返回已经落库的本地凭证快照。
func (s *BootstrapCoordinatorService) EnsureModuleReady(ctx context.Context) (*commonif.ModuleCredentialSnapshot, error) {
	if s == nil {
		return nil, &modelsystem.ErrModuleCredentialDependenciesRequired
	}
	if s.runtime.RunMode == modelsystem.RuntimeRunModeNoAuth {
		return nil, nil
	}
	if s.bootstrapExecutor == nil || s.localCredentialMgr == nil {
		return nil, &modelsystem.ErrModuleCredentialDependenciesRequired
	}

	if _, err := s.bootstrapExecutor.EnsureReady(
		ctx,
		&BootstrapStartupRequest{
			Runtime:              s.runtime,
			StartupParams:        s.startupParams,
			AuthAuthorityService: s.authAuthorityService,
		},
	); err != nil {
		return nil, err
	}

	snapshot, err := s.loadCredentialSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	if !commonsvc.IsCredentialValidForDiscovery(snapshot, time.Now()) {
		return nil, fmt.Errorf("bootstrap credential is not valid for discovery")
	}
	return snapshot, nil
}

// RefreshModuleCredential 执行运行期 refresh，并持久化新的凭证快照。
func (s *BootstrapCoordinatorService) RefreshModuleCredential(ctx context.Context) (*commonif.ModuleCredentialSnapshot, error) {
	if s == nil {
		return nil, &modelsystem.ErrModuleCredentialDependenciesRequired
	}
	if s.runtime.RunMode == modelsystem.RuntimeRunModeNoAuth {
		return nil, nil
	}
	if s.localCredentialMgr == nil {
		return nil, &modelsystem.ErrModuleCredentialDependenciesRequired
	}

	snapshot, err := s.loadCredentialSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	if snapshot == nil {
		return nil, fmt.Errorf("credential snapshot is missing")
	}

	refreshed, refreshErr := s.refreshCredentialSnapshot(ctx, snapshot)
	if refreshErr != nil {
		_ = s.localCredentialMgr.MarkCredentialExpired(
			ctx,
			s.principalID(),
			refreshErr.Error(),
		)
		return nil, refreshErr
	}
	if refreshed == nil {
		return nil, fmt.Errorf("refreshed credential snapshot is nil")
	}

	if _, saveErr := s.localCredentialMgr.SaveBootstrapCredential(ctx, refreshed); saveErr != nil {
		_ = s.localCredentialMgr.MarkCredentialExpired(ctx, s.principalID(), saveErr.Error())
		return nil, fmt.Errorf("save refreshed credential failed: %w", saveErr)
	}
	return refreshed, nil
}

// RevokeModuleCredential 将当前模块凭证标记为失效，供外部协调器退出可发现状态。
func (s *BootstrapCoordinatorService) RevokeModuleCredential(ctx context.Context, reason string) error {
	if s == nil {
		return &modelsystem.ErrModuleCredentialDependenciesRequired
	}
	if s.runtime.RunMode == modelsystem.RuntimeRunModeNoAuth {
		return nil
	}
	if s.localCredentialMgr == nil {
		return &modelsystem.ErrModuleCredentialDependenciesRequired
	}
	return s.localCredentialMgr.MarkCredentialExpired(ctx, s.principalID(), reason)
}

func (s *BootstrapCoordinatorService) loadCredentialSnapshot(
	ctx context.Context,
) (*commonif.ModuleCredentialSnapshot, error) {
	if s.localCredentialMgr == nil {
		return nil, &modelsystem.ErrModuleCredentialDependenciesRequired
	}
	return s.localCredentialMgr.LoadActiveCredential(ctx, s.principalID())
}

func (s *BootstrapCoordinatorService) refreshCredentialSnapshot(
	ctx context.Context,
	snapshot *commonif.ModuleCredentialSnapshot,
) (*commonif.ModuleCredentialSnapshot, error) {
	if snapshot == nil {
		return nil, fmt.Errorf("credential snapshot is nil")
	}
	if snapshot.Metadata == nil {
		snapshot.Metadata = make(map[string]string)
	}
	endpoint := s.refreshAuthorityEndpoint(snapshot)
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
	return buildRefreshedCredentialSnapshot(snapshot, bundle, time.Now())
}

func (s *BootstrapCoordinatorService) refreshAuthorityEndpoint(snapshot *commonif.ModuleCredentialSnapshot) string {
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

func (s *BootstrapCoordinatorService) principalID() string {
	entityType := normalizeBootstrapEntityType(s.runtime.EntityType)
	entityID := strings.TrimSpace(s.runtime.InstanceID)
	if entityID == "" {
		entityID = strings.TrimSpace(s.runtime.ServiceName)
	}
	return fmt.Sprintf("%s:%s", entityType, entityID)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
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
