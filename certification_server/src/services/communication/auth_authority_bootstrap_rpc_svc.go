package communication

import (
	"context"
	"strings"
	"time"

	communicationif "certification_server/src/iface/communication"
	orchestrationif "certification_server/src/iface/orchestration"
	authmodel "certification_server/src/models/auth"
	commonmodel "certification_server/src/models/common"
	commsecmodel "certification_server/src/models/commsec"
	modelsystem "certification_server/src/models/system"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	bootstrapServiceName            = "bms.auth.v1.AuthAuthorityBootstrapService"
	bootstrapInitMethodName         = "InitBootstrapChallenge"
	bootstrapAuthenticateMethodName = "AuthenticateBootstrap"
	bootstrapChallengeRouteKey      = "auth.bootstrap.challenge"
	bootstrapAuthenticateRouteKey   = "auth.bootstrap.authenticate"
	bootstrapStageReady             = "BOOTSTRAP_STAGE_READY"
)

type authAuthorityBootstrapRPCServer interface {
	InitBootstrapChallenge(context.Context, *structpb.Struct) (*structpb.Struct, error)
	AuthenticateBootstrap(context.Context, *structpb.Struct) (*structpb.Struct, error)
}

// AuthAuthorityBootstrapRPCService 提供 bootstrap 最小真实调用能力。
// 该实现采用 structpb 作为跨模块的临时传输契约，避免在本阶段引入代码生成。
type AuthAuthorityBootstrapRPCService struct {
	orchestrator   orchestrationif.IAuthRequestOrchestrator
	trafficStation communicationif.ITrafficStation
}

func NewAuthAuthorityBootstrapRPCService(
	orchestrator orchestrationif.IAuthRequestOrchestrator,
	trafficStation communicationif.ITrafficStation,
) *AuthAuthorityBootstrapRPCService {
	return &AuthAuthorityBootstrapRPCService{
		orchestrator:   orchestrator,
		trafficStation: trafficStation,
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
	server.RegisterService(&authAuthorityBootstrapServiceDesc, NewAuthAuthorityBootstrapRPCService(orchestrator, trafficStation))
}

func (s *AuthAuthorityBootstrapRPCService) InitBootstrapChallenge(
	ctx context.Context, req *structpb.Struct,
) (*structpb.Struct, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "challenge request payload is required")
	}
	if s.orchestrator == nil || s.trafficStation == nil {
		return nil, status.Error(codes.Internal, modelsystem.ErrBootstrapRPCDependenciesRequired.Error())
	}

	payload := req.AsMap()
	if err := s.ensureInboundAccepted(ctx, payload, bootstrapInitMethodName); err != nil {
		return nil, err
	}

	challenge, err := s.orchestrator.HandleBootstrapChallenge(
		ctx,
		mapStructToChallengeRequest(payload),
	)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "init bootstrap challenge failed: %v", err)
	}
	resp, err := buildChallengeResponse(challenge)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "build challenge response failed: %v", err)
	}
	return resp, nil
}

func (s *AuthAuthorityBootstrapRPCService) AuthenticateBootstrap(
	ctx context.Context, req *structpb.Struct,
) (*structpb.Struct, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "bootstrap auth payload is required")
	}
	if s.orchestrator == nil || s.trafficStation == nil {
		return nil, status.Error(codes.Internal, modelsystem.ErrBootstrapRPCDependenciesRequired.Error())
	}

	payload := req.AsMap()
	if err := s.ensureInboundAccepted(ctx, payload, bootstrapAuthenticateMethodName); err != nil {
		return nil, err
	}

	authReq, err := mapStructToBootstrapAuthRequest(payload)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid bootstrap auth payload: %v", err)
	}

	result, err := s.orchestrator.HandleBootstrapAuthenticate(ctx, authReq)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "authenticate bootstrap failed: %v", err)
	}

	resp, err := buildBootstrapAuthResponse(result)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "build bootstrap auth response failed: %v", err)
	}
	return resp, nil
}

func (s *AuthAuthorityBootstrapRPCService) ensureInboundAccepted(
	ctx context.Context,
	payload map[string]any,
	methodName string,
) error {
	decision, err := s.trafficStation.HandleInbound(
		ctx,
		&communicationif.InboundTrafficRequest{
			Route:   buildBootstrapRoutingInput(payload, methodName),
			Headers: buildBootstrapInboundHeaders(payload),
			Payload: "",
		},
	)
	if err != nil {
		return status.Errorf(codes.Internal, "inbound traffic station failed: %v", err)
	}
	if decision == nil {
		return status.Error(codes.Internal, "inbound traffic decision is nil")
	}
	if !decision.Accepted {
		reason := strings.TrimSpace(decision.Reason)
		if reason == "" {
			reason = "rejected"
		}
		return status.Errorf(codes.PermissionDenied, "inbound traffic rejected: %s", reason)
	}
	return nil
}

func buildBootstrapRoutingInput(payload map[string]any, methodName string) *communicationif.RoutingInput {
	routeKey := resolveBootstrapRouteKey(methodName)
	path := "/" + bootstrapServiceName + "/" + strings.TrimSpace(methodName)
	metadata := map[string]string{
		"grpc_service": bootstrapServiceName,
		"grpc_method":  strings.TrimSpace(methodName),
		"operation":    strings.TrimSpace(methodName),
	}

	requestID := readString(payload, "request_id")
	if requestID != "" {
		metadata["request_id"] = requestID
	}
	traceID := readString(payload, "trace_id")
	if traceID != "" {
		metadata["trace_id"] = traceID
	}

	return &communicationif.RoutingInput{
		RouteKey:          routeKey,
		Transport:         "grpc",
		Method:            "POST",
		Path:              path,
		SourceService:     resolveBootstrapSourceService(payload),
		TargetService:     "certification_server",
		TargetServiceHint: "certification_server",
		Metadata:          metadata,
	}
}

func buildBootstrapInboundHeaders(payload map[string]any) map[string]string {
	headers := map[string]string{}

	if requestID := readString(payload, "request_id"); requestID != "" {
		headers["x-request-id"] = requestID
	}
	if traceID := readString(payload, "trace_id"); traceID != "" {
		headers["x-trace-id"] = traceID
	}
	if clientID := readString(payload, "client_id"); clientID != "" {
		headers["x-client-id"] = clientID
	}
	if gatewayID := readString(payload, "gateway_id"); gatewayID != "" {
		headers["x-gateway-id"] = gatewayID
	}
	if sourceIP := readString(payload, "source_ip"); sourceIP != "" {
		headers["x-source-ip"] = sourceIP
	}
	if userAgent := readString(payload, "user_agent"); userAgent != "" {
		headers["x-user-agent"] = userAgent
	}

	if challenge := readMap(payload, "challenge"); len(challenge) > 0 {
		if requestID := readString(challenge, "request_id"); requestID != "" {
			headers["x-request-id"] = requestID
		}
		if traceID := readString(challenge, "trace_id"); traceID != "" {
			headers["x-trace-id"] = traceID
		}
		if gatewayID := readString(challenge, "gateway_id"); gatewayID != "" {
			headers["x-gateway-id"] = gatewayID
		}
	}

	return headers
}

func resolveBootstrapRouteKey(methodName string) string {
	switch strings.TrimSpace(methodName) {
	case bootstrapInitMethodName:
		return bootstrapChallengeRouteKey
	case bootstrapAuthenticateMethodName:
		return bootstrapAuthenticateRouteKey
	default:
		return bootstrapAuthenticateRouteKey
	}
}

func resolveBootstrapSourceService(payload map[string]any) string {
	if sourceService := readString(payload, "source_service"); sourceService != "" {
		return sourceService
	}
	if entityID := readString(payload, "entity_id"); entityID != "" {
		return entityID
	}
	if challenge := readMap(payload, "challenge"); len(challenge) > 0 {
		if entityID := readString(challenge, "entity_id"); entityID != "" {
			return entityID
		}
	}
	return "unknown_source"
}

func mapStructToChallengeRequest(input map[string]any) *authmodel.ChallengeRequest {
	ttlSec := readInt64(input, "ttl_sec", 60)
	if ttlSec <= 0 {
		ttlSec = 60
	}

	return &authmodel.ChallengeRequest{
		EntityType: parseEntityType(readString(input, "entity_type")),
		EntityID:   readString(input, "entity_id"),
		KeyID:      readString(input, "key_id"),
		Audience:   readString(input, "audience"),
		ClientID:   readString(input, "client_id"),
		GatewayID:  readString(input, "gateway_id"),
		SourceIP:   readString(input, "source_ip"),
		UserAgent:  readString(input, "user_agent"),
		RequestID:  readString(input, "request_id"),
		TraceID:    readString(input, "trace_id"),
		TTLSec:     ttlSec,
	}
}

func mapStructToBootstrapAuthRequest(input map[string]any) (*authmodel.BootstrapAuthRequest, error) {
	challengeMap := readMap(input, "challenge")
	if len(challengeMap) == 0 {
		return nil, status.Error(codes.InvalidArgument, "challenge payload is required")
	}

	challengeID, err := parseUUID(readString(challengeMap, "challenge_id"))
	if err != nil {
		return nil, err
	}
	challenge := authmodel.ChallengePayload{
		ChallengeID: challengeID,
		Issuer:      readString(challengeMap, "issuer"),
		Audience:    readString(challengeMap, "audience"),
		EntityType:  parseEntityType(readString(challengeMap, "entity_type")),
		EntityID:    readString(challengeMap, "entity_id"),
		KeyID:       readString(challengeMap, "key_id"),
		Nonce:       readString(challengeMap, "nonce"),
		IssuedAt:    parseUnixMillis(readInt64(challengeMap, "issued_at_ms", time.Now().UTC().UnixMilli())),
		ExpiresAt:   parseUnixMillis(readInt64(challengeMap, "expires_at_ms", time.Now().UTC().Add(60*time.Second).UnixMilli())),
	}

	signedMap := readMap(input, "signed")
	signedChallengeID := challengeID
	if candidate := readString(signedMap, "challenge_id"); candidate != "" {
		signedChallengeID, err = parseUUID(candidate)
		if err != nil {
			return nil, err
		}
	}
	signed := authmodel.SignedChallengeResponse{
		ChallengeID:        signedChallengeID,
		KeyID:              readString(signedMap, "key_id"),
		SignatureAlgorithm: parseSignatureAlgorithm(readString(signedMap, "signature_algorithm")),
		Signature:          readString(signedMap, "signature"),
		SignedAt:           parseUnixMillis(readInt64(signedMap, "signed_at_ms", time.Now().UTC().UnixMilli())),
	}

	return &authmodel.BootstrapAuthRequest{
		Challenge:              challenge,
		Signed:                 signed,
		Scopes:                 readStringSlice(input, "scopes"),
		Role:                   readString(input, "role"),
		RequireDownstreamToken: readBool(input, "require_downstream_token"),
	}, nil
}

func buildChallengeResponse(challenge *authmodel.ChallengePayload) (*structpb.Struct, error) {
	if challenge == nil {
		return structpb.NewStruct(map[string]any{"challenge": map[string]any{}})
	}

	return structpb.NewStruct(map[string]any{
		"challenge": map[string]any{
			"challenge_id":  challenge.ChallengeID.String(),
			"issuer":        challenge.Issuer,
			"audience":      challenge.Audience,
			"entity_type":   string(challenge.EntityType),
			"entity_id":     challenge.EntityID,
			"key_id":        challenge.KeyID,
			"nonce":         challenge.Nonce,
			"issued_at_ms":  float64(challenge.IssuedAt.UnixMilli()),
			"expires_at_ms": float64(challenge.ExpiresAt.UnixMilli()),
		},
	})
}

func buildBootstrapAuthResponse(result *authmodel.BootstrapAuthResult) (*structpb.Struct, error) {
	if result == nil {
		return structpb.NewStruct(map[string]any{})
	}

	identity := map[string]any{}
	if result.Identity != nil {
		principal := map[string]any{
			"entity_type":  string(result.Identity.Principal.EntityType),
			"entity_id":    result.Identity.Principal.EntityID,
			"principal_id": result.Identity.Principal.PrincipalID(),
		}
		identity = map[string]any{
			"principal":       principal,
			"entity_type":     string(result.Identity.EntityType),
			"entity_id":       result.Identity.EntityID,
			"principal_id":    result.Identity.PrincipalID,
			"session_id":      uuidToString(result.Identity.SessionID),
			"token_id":        uuidToString(result.Identity.TokenID),
			"token_family_id": uuidToString(result.Identity.TokenFamilyID),
			"role":            result.Identity.Role,
			"scopes":          toAnySlice(result.Identity.Scopes),
			"auth_method":     string(result.Identity.AuthMethod),
			"source_ip":       result.Identity.SourceIP,
			"client_id":       result.Identity.ClientID,
			"gateway_id":      result.Identity.GatewayID,
			"source_service":  result.Identity.SourceService,
			"target_service":  result.Identity.TargetService,
			"request_id":      result.Identity.RequestID,
			"trace_id":        result.Identity.TraceID,
			"issued_at_ms":    float64(result.Identity.IssuedAt.UnixMilli()),
			"expires_at_ms":   float64(result.Identity.ExpiresAt.UnixMilli()),
		}
	}

	session := map[string]any{}
	if result.Session != nil {
		session = map[string]any{
			"session_id": uuidToString(result.Session.ID),
			"principal": map[string]any{
				"entity_type":  string(result.Session.Principal.EntityType),
				"entity_id":    result.Session.Principal.EntityID,
				"principal_id": result.Session.Principal.PrincipalID(),
			},
			"status":         string(result.Session.Status),
			"auth_method":    string(result.Session.AuthMethod),
			"client_id":      result.Session.ClientID,
			"gateway_id":     result.Session.GatewayID,
			"scope_snapshot": toAnySlice(result.Session.ScopeSnapshot),
			"role_snapshot":  result.Session.RoleSnapshot,
			"created_at_ms":  float64(result.Session.CreatedAt.UnixMilli()),
			"expires_at_ms":  float64(result.Session.ExpiresAt.UnixMilli()),
			"version":        float64(result.Session.Version),
		}
	}

	tokens := map[string]any{}
	if issued := buildIssuedTokenMap(result.Tokens.AccessToken); len(issued) > 0 {
		tokens["access_token"] = issued
	}
	if issued := buildIssuedTokenMap(result.Tokens.RefreshToken); len(issued) > 0 {
		tokens["refresh_token"] = issued
	}
	if issued := buildIssuedTokenMap(result.Tokens.DownstreamToken); len(issued) > 0 {
		tokens["downstream_token"] = issued
	}

	stage := mapStage(result.Stage)
	if stage == "" {
		stage = bootstrapStageReady
	}

	return structpb.NewStruct(map[string]any{
		"stage":              stage,
		"identity":           identity,
		"session":            session,
		"tokens":             tokens,
		"active_comm_key_id": strings.TrimSpace(result.ActiveCommKeyID),
		"issued_at_ms":       float64(result.IssuedAt.UnixMilli()),
		"expires_at_ms":      float64(result.ExpiresAt.UnixMilli()),
	})
}

func mapStage(stage authmodel.BootstrapStage) string {
	resolved := strings.TrimSpace(strings.ToLower(string(stage)))
	switch resolved {
	case "ready":
		return "BOOTSTRAP_STAGE_READY"
	case "challenging":
		return "BOOTSTRAP_STAGE_CHALLENGING"
	case "authenticating":
		return "BOOTSTRAP_STAGE_AUTHENTICATING"
	case "uninitialized":
		return "BOOTSTRAP_STAGE_UNINITIALIZED"
	default:
		return strings.TrimSpace(string(stage))
	}
}

func buildIssuedTokenMap(token *authmodel.IssuedToken) map[string]any {
	if token == nil {
		return nil
	}
	return map[string]any{
		"raw":        token.Raw,
		"token_type": mapTokenType(token.Type),
		"ttl_sec":    float64(token.TTLSec),
	}
}

func mapTokenType(tokenType authmodel.TokenType) string {
	resolved := strings.TrimSpace(strings.ToLower(string(tokenType)))
	switch resolved {
	case "access":
		return "TOKEN_TYPE_ACCESS"
	case "refresh":
		return "TOKEN_TYPE_REFRESH"
	case "downstream":
		return "TOKEN_TYPE_DOWNSTREAM"
	default:
		return strings.TrimSpace(string(tokenType))
	}
}

func parseEntityType(raw string) commonmodel.EntityType {
	resolved := strings.TrimSpace(strings.ToLower(raw))
	switch commonmodel.EntityType(resolved) {
	case commonmodel.EntityUser, commonmodel.EntityDevice, commonmodel.EntityService:
		return commonmodel.EntityType(resolved)
	default:
		return commonmodel.EntityService
	}
}

func parseSignatureAlgorithm(raw string) commsecmodel.SignatureAlgorithm {
	resolved := strings.TrimSpace(strings.ToLower(raw))
	switch resolved {
	case "ecdsa_p256_sha256", "signature_algorithm_ecdsa_p256_sha256":
		return commsecmodel.SignatureECDSAP256SHA256
	case "rsa_pss_sha256", "signature_algorithm_rsa_pss_sha256":
		return commsecmodel.SignatureRSAPSSSHA256
	default:
		return commsecmodel.SignatureEd25519
	}
}

func parseUUID(raw string) (uuid.UUID, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return uuid.Nil, status.Error(codes.InvalidArgument, "challenge_id is required")
	}
	parsed, err := uuid.Parse(trimmed)
	if err != nil {
		return uuid.Nil, status.Errorf(codes.InvalidArgument, "invalid uuid: %v", err)
	}
	return parsed, nil
}

func parseUnixMillis(ms int64) time.Time {
	if ms <= 0 {
		return time.Now().UTC()
	}
	return time.UnixMilli(ms).UTC()
}

func uuidToString(id uuid.UUID) string {
	if id == uuid.Nil {
		return ""
	}
	return id.String()
}

func readString(m map[string]any, key string) string {
	if len(m) == 0 {
		return ""
	}
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

func readInt64(m map[string]any, key string, fallback int64) int64 {
	if len(m) == 0 {
		return fallback
	}
	v, ok := m[key]
	if !ok || v == nil {
		return fallback
	}
	n, ok := v.(float64)
	if !ok {
		return fallback
	}
	return int64(n)
}

func readBool(m map[string]any, key string) bool {
	if len(m) == 0 {
		return false
	}
	v, ok := m[key]
	if !ok || v == nil {
		return false
	}
	b, ok := v.(bool)
	if ok {
		return b
	}
	text, ok := v.(string)
	if !ok {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(text), "true")
}

func readMap(m map[string]any, key string) map[string]any {
	if len(m) == 0 {
		return nil
	}
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	child, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	return child
}

func readStringSlice(m map[string]any, key string) []string {
	if len(m) == 0 {
		return nil
	}
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		s, ok := item.(string)
		if !ok {
			continue
		}
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		out = append(out, s)
	}
	return out
}

func toAnySlice(values []string) []any {
	out := make([]any, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}

func authAuthorityBootstrapInitHandler(
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	in := new(structpb.Struct)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(authAuthorityBootstrapRPCServer).InitBootstrapChallenge(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/" + bootstrapServiceName + "/" + bootstrapInitMethodName,
	}
	handler := func(execCtx context.Context, req any) (any, error) {
		return srv.(authAuthorityBootstrapRPCServer).InitBootstrapChallenge(execCtx, req.(*structpb.Struct))
	}
	return interceptor(ctx, in, info, handler)
}

func authAuthorityBootstrapAuthenticateHandler(
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	in := new(structpb.Struct)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(authAuthorityBootstrapRPCServer).AuthenticateBootstrap(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/" + bootstrapServiceName + "/" + bootstrapAuthenticateMethodName,
	}
	handler := func(execCtx context.Context, req any) (any, error) {
		return srv.(authAuthorityBootstrapRPCServer).AuthenticateBootstrap(execCtx, req.(*structpb.Struct))
	}
	return interceptor(ctx, in, info, handler)
}

var authAuthorityBootstrapServiceDesc = grpc.ServiceDesc{
	ServiceName: bootstrapServiceName,
	HandlerType: (*authAuthorityBootstrapRPCServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: bootstrapInitMethodName,
			Handler:    authAuthorityBootstrapInitHandler,
		},
		{
			MethodName: bootstrapAuthenticateMethodName,
			Handler:    authAuthorityBootstrapAuthenticateHandler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "schemas/proto/auth/v1/auth_authority_bootstrap.proto",
}
