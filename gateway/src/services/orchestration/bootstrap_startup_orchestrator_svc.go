package orchestration

import (
	"context"
	"fmt"
	"strings"
	"time"

	commonif "gateway/src/iface/common"
	communicationif "gateway/src/iface/communication"
	authmodel "gateway/src/models/auth"
	commonmodel "gateway/src/models/common"
	modelsystem "gateway/src/models/system"
	communicationsvc "gateway/src/services/communication"
)

const defaultBootstrapAuthorityServiceName = "certification_server"
const bootstrapAuthenticateRouteKey = "auth.bootstrap.authenticate"

// BootstrapStartupRequest 是网关启动阶段 bootstrap 编排输入。
type BootstrapStartupRequest struct {
	Runtime              modelsystem.RuntimeConfig
	StartupParams        modelsystem.SecretKeyStartupParams
	AuthAuthorityService string
}

// BootstrapStartupResult 是网关启动阶段 bootstrap 编排输出。
type BootstrapStartupResult struct {
	Stage             string
	AuthorityEndpoint string
	CredentialKey     string
}

// BootstrapStartupOrchestratorService 将启动期 bootstrap 逻辑下沉到编排层。
type BootstrapStartupOrchestratorService struct {
	localCredentialMgr  commonif.ILocalCredentialManager
	trafficStation      communicationif.ITrafficStation
	authAuthorityTarget string
}

func NewBootstrapStartupOrchestratorService(
	localCredentialMgr commonif.ILocalCredentialManager,
	trafficStation communicationif.ITrafficStation,
	authAuthorityService string,
) *BootstrapStartupOrchestratorService {
	resolvedAuthority := strings.TrimSpace(authAuthorityService)
	if resolvedAuthority == "" {
		resolvedAuthority = defaultBootstrapAuthorityServiceName
	}

	return &BootstrapStartupOrchestratorService{
		localCredentialMgr:  localCredentialMgr,
		trafficStation:      trafficStation,
		authAuthorityTarget: resolvedAuthority,
	}
}

func (s *BootstrapStartupOrchestratorService) EnsureReady(
	ctx context.Context,
	req *BootstrapStartupRequest,
) (*BootstrapStartupResult, error) {
	if req == nil {
		return nil, &modelsystem.ErrReadinessRequestInvalid
	}
	if s.localCredentialMgr == nil {
		return nil, &modelsystem.ErrModuleCredentialDependenciesRequired
	}

	runtime := req.Runtime
	startupParams := req.StartupParams

	if strings.TrimSpace(startupParams.ActiveKeyID) == "" && strings.TrimSpace(runtime.InstanceID) == "" {
		return nil, fmt.Errorf("bootstrap identity requires active_key_id or instance_id")
	}

	authorityService := strings.TrimSpace(req.AuthAuthorityService)
	if authorityService == "" {
		authorityService = s.authAuthorityTarget
	}
	authorityEndpoint, err := s.resolveAuthorityEndpoint(ctx, runtime, authorityService)
	if err != nil {
		return nil, err
	}

	keyID := strings.TrimSpace(startupParams.ActiveKeyID)
	if keyID == "" {
		keyID = strings.TrimSpace(runtime.InstanceID)
	}

	bootstrapClient := communicationsvc.NewBootstrapRPCClient(authorityEndpoint)
	handshakeResult, callErr := bootstrapClient.ExecuteBootstrapHandshake(
		ctx,
		&communicationsvc.BootstrapHandshakeRequest{
			EntityType: runtime.EntityType,
			EntityID:   runtime.InstanceID,
			Audience:   runtime.ServiceName,
			KeyID:      keyID,
		},
	)
	if callErr != nil {
		return nil, fmt.Errorf("bootstrap handshake failed: %w", callErr)
	}
	if !strings.EqualFold(handshakeResult.Stage, string(authmodel.BootstrapStageReady)) {
		return nil, fmt.Errorf("bootstrap handshake stage is not ready: %s", handshakeResult.Stage)
	}

	now := time.Now()
	entityType := normalizeBootstrapEntityType(runtime.EntityType)
	entityID := strings.TrimSpace(runtime.InstanceID)
	if entityID == "" {
		entityID = strings.TrimSpace(runtime.ServiceName)
	}
	principalID := fmt.Sprintf("%s:%s", entityType, entityID)

	activeCommKeyID := strings.TrimSpace(handshakeResult.ActiveCommKeyID)
	if activeCommKeyID == "" {
		activeCommKeyID = keyID
	}
	credentialKey, saveErr := s.localCredentialMgr.SaveBootstrapCredential(
		ctx,
		&commonif.ModuleCredentialSnapshot{
			PrincipalID:     principalID,
			EntityType:      entityType,
			EntityID:        entityID,
			Stage:           authmodel.BootstrapStageReady,
			ActiveCommKeyID: activeCommKeyID,
			IssuedAt:        now,
			ExpiresAt:       now.Add(15 * time.Minute),
			UpdatedAt:       now,
			Metadata: map[string]string{
				"run_mode":            string(runtime.RunMode),
				"auth_authority":      authorityService,
				"auth_authority_ep":   authorityEndpoint,
				"credential_status":   "active",
				"bootstrap_rpc_stage": handshakeResult.Stage,
			},
		},
	)
	if saveErr != nil {
		return nil, fmt.Errorf("save bootstrap credential failed: %w", saveErr)
	}

	return &BootstrapStartupResult{
		Stage:             handshakeResult.Stage,
		AuthorityEndpoint: authorityEndpoint,
		CredentialKey:     credentialKey,
	}, nil
}

func (s *BootstrapStartupOrchestratorService) resolveAuthorityEndpoint(
	ctx context.Context,
	runtime modelsystem.RuntimeConfig,
	authorityService string,
) (string, error) {
	if s.trafficStation == nil {
		return "", &modelsystem.ErrForwardingDependenciesRequired
	}

	dispatch, err := s.trafficStation.SendOutbound(
		ctx,
		&communicationif.OutboundTrafficRequest{
			Flow: &commonif.FlowRouteInput{
				RouteKey:          bootstrapAuthenticateRouteKey,
				Transport:         "grpc",
				Method:            "POST",
				Path:              "/bms.auth.v1.AuthAuthorityBootstrapService/AuthenticateBootstrap",
				SourceService:     runtime.ServiceName,
				TargetServiceHint: authorityService,
				Metadata: map[string]string{
					"startup_phase":         "bootstrap",
					"trusted_internal_call": "true",
				},
			},
			Headers: map[string]string{},
			Payload: "",
		},
	)
	if err != nil {
		return "", fmt.Errorf("auth authority is not discoverable: %w", err)
	}
	if dispatch == nil || strings.TrimSpace(dispatch.TargetEndpoint) == "" {
		return "", fmt.Errorf("auth authority endpoint is empty")
	}
	return strings.TrimSpace(dispatch.TargetEndpoint), nil
}

func normalizeBootstrapEntityType(raw string) commonmodel.EntityType {
	entityType := strings.TrimSpace(strings.ToLower(raw))
	switch commonmodel.EntityType(entityType) {
	case commonmodel.EntityUser, commonmodel.EntityDevice, commonmodel.EntityService:
		return commonmodel.EntityType(entityType)
	default:
		return commonmodel.EntityService
	}
}
