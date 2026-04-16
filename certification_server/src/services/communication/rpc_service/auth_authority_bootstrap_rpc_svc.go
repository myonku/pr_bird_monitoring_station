package rpcservice

import (
	"context"
	"strings"
	"time"

	authv1 "certification_server/src/gen/auth/v1"
	communicationif "certification_server/src/iface/communication"
	orchestrationif "certification_server/src/iface/orchestration"
	authmodel "certification_server/src/models/auth"
	commonmodel "certification_server/src/models/common"
	commsecmodel "certification_server/src/models/commsec"
	communication "certification_server/src/services/communication"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const bootstrapServiceName = "bms.auth.v1.AuthAuthorityBootstrapService"

// AuthAuthorityBootstrapRPCService 提供 bootstrap 最小真实 proto 调用能力。
type AuthAuthorityBootstrapRPCService struct {
	authv1.UnimplementedAuthAuthorityBootstrapServiceServer

	bootstrapHandler *BootstrapFlowHandler
}

func NewAuthAuthorityBootstrapRPCService(
	orchestrator orchestrationif.IAuthRequestOrchestrator,
	trafficStation communicationif.ITrafficStation,
) *AuthAuthorityBootstrapRPCService {
	return &AuthAuthorityBootstrapRPCService{
		bootstrapHandler: NewBootstrapFlowHandler(orchestrator, trafficStation),
	}
}

// RegisterAuthAuthorityBootstrapRPC 将 bootstrap gRPC 服务注册到认证中心。
func RegisterAuthAuthorityBootstrapRPC(
	server *grpc.Server,
	orchestrator orchestrationif.IAuthRequestOrchestrator,
	trafficStation communicationif.ITrafficStation,
) {
	if server == nil {
		return
	}
	authv1.RegisterAuthAuthorityBootstrapServiceServer(
		server,
		NewAuthAuthorityBootstrapRPCService(orchestrator, trafficStation),
	)
}

func (s *AuthAuthorityBootstrapRPCService) InitBootstrapChallenge(
	ctx context.Context,
	req *authv1.BootstrapChallengeRequest,
) (*authv1.BootstrapChallengeResponse, error) {
	if s.bootstrapHandler == nil {
		return nil, status.Error(codes.Internal, "bootstrap flow handler is required")
	}
	return s.bootstrapHandler.HandleBootstrapChallenge(
		ctx,
		req,
		buildBootstrapChallengeRoutingInput(req),
		buildBootstrapChallengeInboundHeaders(req),
	)
}

func (s *AuthAuthorityBootstrapRPCService) AuthenticateBootstrap(
	ctx context.Context,
	req *authv1.BootstrapAuthenticateRequest,
) (*authv1.BootstrapAuthenticateResponse, error) {
	if s.bootstrapHandler == nil {
		return nil, status.Error(codes.Internal, "bootstrap flow handler is required")
	}
	return s.bootstrapHandler.HandleBootstrapAuthenticate(
		ctx,
		req,
		buildBootstrapAuthenticateRoutingInput(req),
		buildBootstrapAuthenticateInboundHeaders(req),
	)
}

func buildBootstrapChallengeRoutingInput(req *authv1.BootstrapChallengeRequest) *communicationif.RoutingInput {
	metadata := map[string]string{
		"grpc_service": bootstrapServiceName,
		"grpc_method":  "InitBootstrapChallenge",
		"operation":    "InitBootstrapChallenge",
	}
	if requestID := strings.TrimSpace(req.GetRequestId()); requestID != "" {
		metadata["request_id"] = requestID
	}
	if traceID := strings.TrimSpace(req.GetTraceId()); traceID != "" {
		metadata["trace_id"] = traceID
	}

	return &communicationif.RoutingInput{
		RouteKey:          communication.BootstrapChallengeRouteKey,
		Transport:         "grpc",
		Method:            "POST",
		Path:              authv1.AuthAuthorityBootstrapService_InitBootstrapChallenge_FullMethodName,
		SourceService:     resolveChallengeSourceService(req),
		TargetService:     "certification_server",
		TargetServiceHint: "certification_server",
		Metadata:          metadata,
	}
}

func buildBootstrapAuthenticateRoutingInput(req *authv1.BootstrapAuthenticateRequest) *communicationif.RoutingInput {
	metadata := map[string]string{
		"grpc_service": bootstrapServiceName,
		"grpc_method":  "AuthenticateBootstrap",
		"operation":    "AuthenticateBootstrap",
	}
	if challenge := req.GetChallenge(); challenge != nil {
		if challengeID := strings.TrimSpace(challenge.GetChallengeId()); challengeID != "" {
			metadata["challenge_id"] = challengeID
		}
	}

	return &communicationif.RoutingInput{
		RouteKey:          communication.BootstrapAuthenticateRouteKey,
		Transport:         "grpc",
		Method:            "POST",
		Path:              authv1.AuthAuthorityBootstrapService_AuthenticateBootstrap_FullMethodName,
		SourceService:     resolveAuthenticateSourceService(req),
		TargetService:     "certification_server",
		TargetServiceHint: "certification_server",
		Metadata:          metadata,
	}
}

func buildBootstrapChallengeInboundHeaders(req *authv1.BootstrapChallengeRequest) map[string]string {
	headers := map[string]string{}

	if requestID := strings.TrimSpace(req.GetRequestId()); requestID != "" {
		headers["x-request-id"] = requestID
	}
	if traceID := strings.TrimSpace(req.GetTraceId()); traceID != "" {
		headers["x-trace-id"] = traceID
	}
	if clientID := strings.TrimSpace(req.GetClientId()); clientID != "" {
		headers["x-client-id"] = clientID
	}
	if gatewayID := strings.TrimSpace(req.GetGatewayId()); gatewayID != "" {
		headers["x-gateway-id"] = gatewayID
	}
	if sourceIP := strings.TrimSpace(req.GetSourceIp()); sourceIP != "" {
		headers["x-source-ip"] = sourceIP
	}
	if userAgent := strings.TrimSpace(req.GetUserAgent()); userAgent != "" {
		headers["x-user-agent"] = userAgent
	}

	return headers
}

func buildBootstrapAuthenticateInboundHeaders(req *authv1.BootstrapAuthenticateRequest) map[string]string {
	headers := map[string]string{}
	if challenge := req.GetChallenge(); challenge != nil {
		if challengeID := strings.TrimSpace(challenge.GetChallengeId()); challengeID != "" {
			headers["x-bootstrap-challenge-id"] = challengeID
		}
	}
	return headers
}

func resolveChallengeSourceService(req *authv1.BootstrapChallengeRequest) string {
	if runtime := req.GetRuntime(); runtime != nil {
		if source := strings.TrimSpace(runtime.GetEntityName()); source != "" {
			return source
		}
		if source := strings.TrimSpace(runtime.GetInstanceName()); source != "" {
			return source
		}
		if source := strings.TrimSpace(runtime.GetInstanceId()); source != "" {
			return source
		}
	}
	if source := strings.TrimSpace(req.GetEntityId()); source != "" {
		return source
	}
	return "unknown_source"
}

func resolveAuthenticateSourceService(req *authv1.BootstrapAuthenticateRequest) string {
	if challenge := req.GetChallenge(); challenge != nil {
		if source := strings.TrimSpace(challenge.GetEntityId()); source != "" {
			return source
		}
	}
	return "unknown_source"
}

func mapProtoChallengeRequest(req *authv1.BootstrapChallengeRequest) (*authmodel.ChallengeRequest, error) {
	ttlSec := req.GetTtlSec()
	if ttlSec <= 0 {
		ttlSec = 60
	}
	entityType, err := mapProtoEntityType(req.GetEntityType())
	if err != nil {
		return nil, err
	}

	return &authmodel.ChallengeRequest{
		EntityType: entityType,
		EntityID:   strings.TrimSpace(req.GetEntityId()),
		KeyID:      strings.TrimSpace(req.GetKeyId()),
		Audience:   strings.TrimSpace(req.GetAudience()),
		ClientID:   strings.TrimSpace(req.GetClientId()),
		GatewayID:  strings.TrimSpace(req.GetGatewayId()),
		SourceIP:   strings.TrimSpace(req.GetSourceIp()),
		UserAgent:  strings.TrimSpace(req.GetUserAgent()),
		RequestID:  strings.TrimSpace(req.GetRequestId()),
		TraceID:    strings.TrimSpace(req.GetTraceId()),
		TTLSec:     ttlSec,
	}, nil
}

func mapProtoBootstrapAuthRequest(req *authv1.BootstrapAuthenticateRequest) (*authmodel.BootstrapAuthRequest, error) {
	challengeProto := req.GetChallenge()
	if challengeProto == nil {
		return nil, status.Error(codes.InvalidArgument, "challenge payload is required")
	}
	signedProto := req.GetSigned()
	if signedProto == nil {
		return nil, status.Error(codes.InvalidArgument, "signed payload is required")
	}

	challengeID, err := parseUUID("challenge.challenge_id", challengeProto.GetChallengeId())
	if err != nil {
		return nil, err
	}
	challengeEntityType, err := mapProtoEntityType(challengeProto.GetEntityType())
	if err != nil {
		return nil, err
	}
	signatureAlgorithm, err := mapProtoSignatureAlgorithm(signedProto.GetSignatureAlgorithm())
	if err != nil {
		return nil, err
	}
	signedChallengeID := challengeID
	if candidate := strings.TrimSpace(signedProto.GetChallengeId()); candidate != "" {
		signedChallengeID, err = parseUUID("signed.challenge_id", candidate)
		if err != nil {
			return nil, err
		}
	}

	issuedAtMs := challengeProto.GetIssuedAtMs()
	if issuedAtMs <= 0 {
		issuedAtMs = time.Now().UTC().UnixMilli()
	}
	expiresAtMs := challengeProto.GetExpiresAtMs()
	if expiresAtMs <= 0 {
		expiresAtMs = time.Now().UTC().Add(60 * time.Second).UnixMilli()
	}
	signedAtMs := signedProto.GetSignedAtMs()
	if signedAtMs <= 0 {
		signedAtMs = time.Now().UTC().UnixMilli()
	}

	return &authmodel.BootstrapAuthRequest{
		Challenge: authmodel.ChallengePayload{
			ChallengeID: challengeID,
			Issuer:      strings.TrimSpace(challengeProto.GetIssuer()),
			Audience:    strings.TrimSpace(challengeProto.GetAudience()),
			EntityType:  challengeEntityType,
			EntityID:    strings.TrimSpace(challengeProto.GetEntityId()),
			KeyID:       strings.TrimSpace(challengeProto.GetKeyId()),
			Nonce:       strings.TrimSpace(challengeProto.GetNonce()),
			IssuedAt:    time.UnixMilli(issuedAtMs).UTC(),
			ExpiresAt:   time.UnixMilli(expiresAtMs).UTC(),
		},
		Signed: authmodel.SignedChallengeResponse{
			ChallengeID:        signedChallengeID,
			KeyID:              strings.TrimSpace(signedProto.GetKeyId()),
			SignatureAlgorithm: signatureAlgorithm,
			Signature:          strings.TrimSpace(signedProto.GetSignature()),
			SignedAt:           time.UnixMilli(signedAtMs).UTC(),
		},
		Scopes:                 append([]string(nil), req.GetScopes()...),
		Role:                   strings.TrimSpace(req.GetRole()),
		RequireDownstreamToken: req.GetRequireDownstreamToken(),
	}, nil
}

func buildChallengeResponse(challenge *authmodel.ChallengePayload) (*authv1.BootstrapChallengeResponse, error) {
	if challenge == nil {
		return &authv1.BootstrapChallengeResponse{}, nil
	}
	entityType, err := mapModelEntityType(challenge.EntityType)
	if err != nil {
		return nil, err
	}

	return &authv1.BootstrapChallengeResponse{
		Challenge: &authv1.ChallengePayload{
			ChallengeId: challenge.ChallengeID.String(),
			Issuer:      strings.TrimSpace(challenge.Issuer),
			Audience:    strings.TrimSpace(challenge.Audience),
			EntityType:  entityType,
			EntityId:    strings.TrimSpace(challenge.EntityID),
			KeyId:       strings.TrimSpace(challenge.KeyID),
			Nonce:       strings.TrimSpace(challenge.Nonce),
			IssuedAtMs:  challenge.IssuedAt.UnixMilli(),
			ExpiresAtMs: challenge.ExpiresAt.UnixMilli(),
		},
	}, nil
}

func buildBootstrapAuthResponse(result *authmodel.BootstrapAuthResult) (*authv1.BootstrapAuthenticateResponse, error) {
	if result == nil {
		return &authv1.BootstrapAuthenticateResponse{}, nil
	}
	identity, err := buildProtoIdentityContext(result.Identity)
	if err != nil {
		return nil, err
	}
	session := buildSessionProto(result.Session)

	return &authv1.BootstrapAuthenticateResponse{
		Stage:           mapBootstrapStage(result.Stage),
		Identity:        identity,
		Session:         session,
		Tokens:          buildTokenBundleProto(result.Tokens),
		ActiveCommKeyId: strings.TrimSpace(result.ActiveCommKeyID),
		IssuedAtMs:      result.IssuedAt.UnixMilli(),
		ExpiresAtMs:     result.ExpiresAt.UnixMilli(),
	}, nil
}

func buildProtoIdentityContext(identity *authmodel.IdentityContext) (*authv1.IdentityContext, error) {
	if identity == nil {
		return nil, nil
	}
	entityType, err := mapModelEntityType(identity.Principal.EntityType)
	if err != nil {
		return nil, err
	}

	principal := &authv1.Principal{
		EntityType:  entityType,
		EntityId:    strings.TrimSpace(identity.Principal.EntityID),
		PrincipalId: strings.TrimSpace(identity.Principal.PrincipalID()),
	}

	return &authv1.IdentityContext{
		Principal:     principal,
		SessionId:     uuidToString(identity.SessionID),
		TokenId:       uuidToString(identity.TokenID),
		TokenFamilyId: uuidToString(identity.TokenFamilyID),
		Role:          strings.TrimSpace(identity.Role),
		Scopes:        append([]string(nil), identity.Scopes...),
		AuthMethod:    strings.TrimSpace(string(identity.AuthMethod)),
		SourceIp:      strings.TrimSpace(identity.SourceIP),
		ClientId:      strings.TrimSpace(identity.ClientID),
		GatewayId:     strings.TrimSpace(identity.GatewayID),
		SourceService: strings.TrimSpace(identity.SourceService),
		TargetService: strings.TrimSpace(identity.TargetService),
		RequestId:     strings.TrimSpace(identity.RequestID),
		TraceId:       strings.TrimSpace(identity.TraceID),
		IssuedAtMs:    identity.IssuedAt.UnixMilli(),
		ExpiresAtMs:   identity.ExpiresAt.UnixMilli(),
	}, nil
}

func mapProtoEntityType(entityType authv1.EntityType) (commonmodel.EntityType, error) {
	switch entityType {
	case authv1.EntityType_ENTITY_TYPE_USER:
		return commonmodel.EntityUser, nil
	case authv1.EntityType_ENTITY_TYPE_DEVICE:
		return commonmodel.EntityDevice, nil
	case authv1.EntityType_ENTITY_TYPE_SERVICE:
		return commonmodel.EntityService, nil
	default:
		return "", status.Errorf(codes.InvalidArgument, "unsupported bootstrap entity_type: %s", entityType.String())
	}
}

func mapModelEntityType(entityType commonmodel.EntityType) (authv1.EntityType, error) {
	switch strings.TrimSpace(strings.ToLower(string(entityType))) {
	case "user":
		return authv1.EntityType_ENTITY_TYPE_USER, nil
	case "device":
		return authv1.EntityType_ENTITY_TYPE_DEVICE, nil
	case "service":
		return authv1.EntityType_ENTITY_TYPE_SERVICE, nil
	default:
		return authv1.EntityType_ENTITY_TYPE_UNSPECIFIED, status.Errorf(codes.Internal, "unsupported model entity_type: %q", strings.TrimSpace(string(entityType)))
	}
}

func mapProtoSignatureAlgorithm(algorithm authv1.SignatureAlgorithm) (commsecmodel.SignatureAlgorithm, error) {
	switch algorithm {
	case authv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519:
		return commsecmodel.SignatureEd25519, nil
	case authv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256:
		return commsecmodel.SignatureECDSAP256SHA256, nil
	case authv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_RSA_PSS_SHA256:
		return commsecmodel.SignatureRSAPSSSHA256, nil
	default:
		return "", status.Errorf(codes.InvalidArgument, "unsupported signature_algorithm: %s", algorithm.String())
	}
}

func mapBootstrapStage(stage authmodel.BootstrapStage) authv1.BootstrapStage {
	switch strings.TrimSpace(strings.ToLower(string(stage))) {
	case "ready":
		return authv1.BootstrapStage_BOOTSTRAP_STAGE_READY
	case "challenging":
		return authv1.BootstrapStage_BOOTSTRAP_STAGE_CHALLENGING
	case "authenticating":
		return authv1.BootstrapStage_BOOTSTRAP_STAGE_AUTHENTICATING
	case "uninitialized":
		return authv1.BootstrapStage_BOOTSTRAP_STAGE_UNINITIALIZED
	default:
		return authv1.BootstrapStage_BOOTSTRAP_STAGE_UNSPECIFIED
	}
}

func mapModelTokenType(tokenType authmodel.TokenType) authv1.TokenType {
	switch strings.TrimSpace(strings.ToLower(string(tokenType))) {
	case "access":
		return authv1.TokenType_TOKEN_TYPE_ACCESS
	case "refresh":
		return authv1.TokenType_TOKEN_TYPE_REFRESH
	case "downstream":
		return authv1.TokenType_TOKEN_TYPE_DOWNSTREAM
	case "service":
		return authv1.TokenType_TOKEN_TYPE_SERVICE
	default:
		return authv1.TokenType_TOKEN_TYPE_UNSPECIFIED
	}
}

func parseUUID(fieldName string, raw string) (uuid.UUID, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return uuid.Nil, status.Errorf(codes.InvalidArgument, "%s is required", fieldName)
	}
	parsed, err := uuid.Parse(trimmed)
	if err != nil {
		return uuid.Nil, status.Errorf(codes.InvalidArgument, "invalid %s: %v", fieldName, err)
	}
	return parsed, nil
}

func uuidToString(id uuid.UUID) string {
	if id == uuid.Nil {
		return ""
	}
	return id.String()
}
