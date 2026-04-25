package orchestration

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	commonif "gateway/src/iface/common"
	communicationif "gateway/src/iface/communication"
	authmodel "gateway/src/models/auth"
	commonmodel "gateway/src/models/common"
	modelsystem "gateway/src/models/system"
	authsvc "gateway/src/services/auth"
	rpcclient "gateway/src/services/communication/rpc_client"
	"gateway/src/utils"

	"github.com/google/uuid"
)

const defaultBootstrapAuthorityServiceName = "certification_server"
const bootstrapAuthenticateRouteKey = "auth.bootstrap.authenticate"

// BootstrapStartupOrchestratorService 将启动期 bootstrap 逻辑下沉到编排层。
type BootstrapStartupOrchestratorService struct {
	localCredentialMgr  commonif.ILocalCredentialManager
	KeyManager          commonif.ISecretKeyManager
	trafficStation      communicationif.ITrafficStation
	authAuthorityTarget string
}

func NewBootstrapStartupOrchestratorService(
	localCredentialMgr commonif.ILocalCredentialManager,
	keyManager commonif.ISecretKeyManager,
	trafficStation communicationif.ITrafficStation,
	authAuthorityService string,
) *BootstrapStartupOrchestratorService {
	resolvedAuthority := strings.TrimSpace(authAuthorityService)
	if resolvedAuthority == "" {
		resolvedAuthority = defaultBootstrapAuthorityServiceName
	}

	return &BootstrapStartupOrchestratorService{
		localCredentialMgr:  localCredentialMgr,
		KeyManager:          keyManager,
		trafficStation:      trafficStation,
		authAuthorityTarget: resolvedAuthority,
	}
}

func (s *BootstrapStartupOrchestratorService) EnsureReady(
	ctx context.Context,
	req *authsvc.BootstrapStartupRequest,
) (*authsvc.BootstrapStartupResult, error) {
	if req == nil {
		return nil, &modelsystem.ErrReadinessRequestInvalid
	}
	if s.localCredentialMgr == nil {
		return nil, &modelsystem.ErrModuleCredentialDependenciesRequired
	}
	if s.KeyManager == nil {
		return nil, &modelsystem.ErrModuleCredentialDependenciesRequired
	}

	runtime := req.Runtime
	startupParams := req.StartupParams

	if strings.TrimSpace(startupParams.ActiveKeyID) == "" && strings.TrimSpace(runtime.InstanceID) == "" {
		return nil, fmt.Errorf("bootstrap identity requires active_key_id or instance_id (entity_id)")
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

	signer, err := s.BuildChallengeSigner(ctx)
	if err != nil {
		return nil, err
	}

	bootstrapClient := rpcclient.NewBootstrapRPCClient(authorityEndpoint)
	handshakeResult, callErr := bootstrapClient.ExecuteBootstrapHandshake(
		ctx,
		&rpcclient.BootstrapHandshakeRequest{
			EntityType: runtime.EntityType,
			EntityID:   runtime.InstanceID,
			Audience:   runtime.ServiceName,
			KeyID:      keyID,
			Signer:     signer,
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

	issuedAt := handshakeResult.IssuedAt
	if issuedAt.IsZero() {
		issuedAt = now
	}
	expiresAt := handshakeResult.ExpiresAt
	if expiresAt.IsZero() && handshakeResult.Session != nil {
		expiresAt = handshakeResult.Session.ExpiresAt
	}
	if expiresAt.IsZero() {
		expiresAt = now.Add(24 * time.Hour)
	}
	refreshExpiresAt := expiresAt
	if refreshToken := handshakeResult.Tokens.RefreshToken; refreshToken != nil && refreshToken.TTLSec > 0 {
		refreshExpiresAt = issuedAt.Add(time.Duration(refreshToken.TTLSec) * time.Second)
	}
	if refreshExpiresAt.IsZero() {
		refreshExpiresAt = expiresAt
	}
	nextRefreshAt := issuedAt.Add(30 * time.Minute)
	if handshakeResult.Session != nil && !handshakeResult.Session.NextRefreshAt.IsZero() {
		nextRefreshAt = handshakeResult.Session.NextRefreshAt
	}
	sessionID := uuidOrZero(handshakeResult.Session)
	tokenFamilyID := uuidOrZeroFromIdentity(handshakeResult.Identity)
	if tokenFamilyID == uuid.Nil && handshakeResult.Session != nil {
		tokenFamilyID = handshakeResult.Session.TokenFamilyID
	}
	accessRaw := tokenRawFromIssuedToken(handshakeResult.Tokens.AccessToken)
	refreshRaw := tokenRawFromIssuedToken(handshakeResult.Tokens.RefreshToken)
	scopes := collectBootstrapScopes(handshakeResult.Identity, handshakeResult.Session)
	role := collectBootstrapRole(handshakeResult.Identity, handshakeResult.Session)

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
			SessionID:       sessionID,
			TokenFamilyID:   tokenFamilyID,
			AccessTokenRaw:  accessRaw,
			RefreshTokenRaw: refreshRaw,
			Scopes:          scopes,
			Role:            role,
			Stage:           authmodel.BootstrapStageReady,
			ActiveCommKeyID: activeCommKeyID,
			IssuedAt:        issuedAt,
			ExpiresAt:       refreshExpiresAt,
			UpdatedAt:       now,
			Metadata: map[string]string{
				"run_mode":              string(runtime.RunMode),
				"auth_authority":        authorityService,
				"auth_authority_ep":     authorityEndpoint,
				"credential_status":     "active",
				"bootstrap_rpc_stage":   handshakeResult.Stage,
				"last_bootstrap_at_ms":  strconv.FormatInt(now.UnixMilli(), 10),
				"last_refresh_at_ms":    strconv.FormatInt(now.UnixMilli(), 10),
				"next_refresh_at_ms":    strconv.FormatInt(nextRefreshAt.UnixMilli(), 10),
				"refresh_expires_at_ms": strconv.FormatInt(refreshExpiresAt.UnixMilli(), 10),
			},
		},
	)
	if saveErr != nil {
		return nil, fmt.Errorf("save bootstrap credential failed: %w", saveErr)
	}

	return &authsvc.BootstrapStartupResult{
		Stage:             handshakeResult.Stage,
		AuthorityEndpoint: authorityEndpoint,
		CredentialKey:     credentialKey,
	}, nil
}

func (s *BootstrapStartupOrchestratorService) BuildChallengeSigner(ctx context.Context) (authmodel.ChallengeSigner, error) {
	if s.KeyManager == nil {
		return nil, &modelsystem.ErrModuleCredentialDependenciesRequired
	}
	publicKey, err := s.KeyManager.GetPublicKey(ctx)
	if err != nil {
		return nil, err
	}
	privateKey, err := s.KeyManager.GetPrivateKeyRef(ctx)
	if err != nil {
		return nil, err
	}
	algorithm, err := (&utils.CryptoUtils{}).DetectSignatureAlgorithmFromPublicPEM([]byte(publicKey.PublicKeyPEM))
	if err != nil {
		return nil, err
	}

	resolvedKeyID := strings.TrimSpace(publicKey.KeyID)
	if resolvedKeyID == "" {
		resolvedKeyID = strings.TrimSpace(privateKey.KeyID)
	}

	return func(signCtx context.Context, payload *authmodel.ChallengePayload) (*authmodel.SignedChallengeResponse, error) {
		_ = signCtx
		if payload == nil {
			return nil, &modelsystem.ErrChallengeRequestNil
		}
		message, err := BuildBootstrapSignaturePayload(payload)
		if err != nil {
			return nil, err
		}
		signature, signErr := (&utils.CryptoUtils{}).SignByAlgorithm(string(algorithm), message, []byte(privateKey.PrivateKeyRef))
		if signErr != nil {
			return nil, signErr
		}
		return &authmodel.SignedChallengeResponse{
			ChallengeID:        payload.ChallengeID,
			KeyID:              resolvedKeyID,
			SignatureAlgorithm: algorithm,
			Signature:          signature,
			SignedAt:           time.Now().UTC(),
		}, nil
	}, nil
}

func BuildBootstrapSignaturePayload(challenge *authmodel.ChallengePayload) ([]byte, error) {
	if challenge == nil {
		return nil, &modelsystem.ErrChallengeRequestNil
	}
	fields := []string{
		strings.TrimSpace(challenge.ChallengeID.String()),
		strings.TrimSpace(challenge.Issuer),
		strings.TrimSpace(challenge.Audience),
		strings.ToLower(strings.TrimSpace(string(challenge.EntityType))),
		strings.TrimSpace(challenge.EntityID),
		strings.TrimSpace(challenge.KeyID),
		strings.TrimSpace(challenge.Nonce),
		challenge.IssuedAt.UTC().Format(time.RFC3339Nano),
		challenge.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}
	return []byte(strings.Join(fields, "|")), nil
}

func tokenRawFromIssuedToken(token *authmodel.IssuedToken) string {
	if token == nil {
		return ""
	}
	return strings.TrimSpace(token.Raw)
}

func uuidOrZero(session *authmodel.Session) (value uuid.UUID) {
	if session == nil {
		return uuid.Nil
	}
	return session.ID
}

func uuidOrZeroFromIdentity(identity *authmodel.IdentityContext) (value uuid.UUID) {
	if identity == nil {
		return uuid.Nil
	}
	return identity.TokenFamilyID
}

func collectBootstrapScopes(identity *authmodel.IdentityContext, session *authmodel.Session) []string {
	if identity != nil && len(identity.Scopes) > 0 {
		return append([]string(nil), identity.Scopes...)
	}
	if session != nil && len(session.ScopeSnapshot) > 0 {
		return append([]string(nil), session.ScopeSnapshot...)
	}
	return []string{}
}

func collectBootstrapRole(identity *authmodel.IdentityContext, session *authmodel.Session) string {
	if identity != nil && strings.TrimSpace(identity.Role) != "" {
		return strings.TrimSpace(identity.Role)
	}
	if session != nil {
		return strings.TrimSpace(session.RoleSnapshot)
	}
	return ""
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
