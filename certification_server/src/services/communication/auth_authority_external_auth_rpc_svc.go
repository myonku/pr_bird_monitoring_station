package communication

import (
	"context"
	"strings"

	authv1 "certification_server/src/gen/auth/v1"
	communicationif "certification_server/src/iface/communication"
	orchestrationif "certification_server/src/iface/orchestration"
	modelsystem "certification_server/src/models/system"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const externalAuthServiceName = "bms.auth.v1.AuthAuthorityExternalAuthService"

// AuthAuthorityExternalAuthRPCService 提供认证中心 external_auth 最小 RPC 服务。
type AuthAuthorityExternalAuthRPCService struct {
	authv1.UnimplementedAuthAuthorityExternalAuthServiceServer

	orchestrator   orchestrationif.IAuthRequestOrchestrator
	trafficStation communicationif.ITrafficStation
	bootstrapFlow  *BootstrapFlowHandler
}

func NewAuthAuthorityExternalAuthRPCService(
	orchestrator orchestrationif.IAuthRequestOrchestrator,
	trafficStation communicationif.ITrafficStation,
) *AuthAuthorityExternalAuthRPCService {
	return &AuthAuthorityExternalAuthRPCService{
		orchestrator:   orchestrator,
		trafficStation: trafficStation,
		bootstrapFlow:  NewBootstrapFlowHandler(orchestrator, trafficStation),
	}
}

// RegisterAuthAuthorityExternalAuthRPC 将 external_auth gRPC 服务注册到认证中心。
func RegisterAuthAuthorityExternalAuthRPC(
	server *grpc.Server,
	orchestrator orchestrationif.IAuthRequestOrchestrator,
	trafficStation communicationif.ITrafficStation,
) {
	if server == nil {
		return
	}
	authv1.RegisterAuthAuthorityExternalAuthServiceServer(
		server,
		NewAuthAuthorityExternalAuthRPCService(orchestrator, trafficStation),
	)
}

func (s *AuthAuthorityExternalAuthRPCService) ForwardUserPassword(
	ctx context.Context,
	req *authv1.UserPasswordAuthRequest,
) (*authv1.UserPasswordAuthResult, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "user password payload is required")
	}
	if s.orchestrator == nil || s.trafficStation == nil {
		return nil, status.Error(codes.Internal, modelsystem.ErrBootstrapRPCDependenciesRequired.Error())
	}

	if err := s.ensureInboundAccepted(
		ctx,
		buildUserPasswordRoutingInput(req),
		buildUserPasswordHeaders(req),
	); err != nil {
		return nil, err
	}

	result, err := s.orchestrator.HandleUserPasswordAuth(
		ctx,
		&orchestrationif.UserPasswordAuthRequest{
			Username:  strings.TrimSpace(req.GetUsername()),
			Password:  req.GetPassword(),
			Audience:  strings.TrimSpace(req.GetAudience()),
			Scopes:    append([]string(nil), req.GetScopes()...),
			ClientID:  strings.TrimSpace(req.GetClientId()),
			GatewayID: strings.TrimSpace(req.GetGatewayId()),
			SourceIP:  strings.TrimSpace(req.GetSourceIp()),
			UserAgent: strings.TrimSpace(req.GetUserAgent()),
			RequestID: strings.TrimSpace(req.GetRequestId()),
			TraceID:   strings.TrimSpace(req.GetTraceId()),
		},
	)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "user password auth failed: %v", err)
	}

	if result == nil {
		return nil, status.Error(codes.Internal, "user password auth result is nil")
	}

	return &authv1.UserPasswordAuthResult{
		Identity:    buildIdentityProto(result.Identity),
		Session:     buildSessionProto(result.Session),
		Tokens:      buildTokenBundleProto(result.Tokens),
		IssuedAtMs:  toUnixMillis(result.IssuedAt),
		ExpiresAtMs: toUnixMillis(result.ExpiresAt),
	}, nil
}

func (s *AuthAuthorityExternalAuthRPCService) ForwardBootstrapChallenge(
	ctx context.Context,
	req *authv1.BootstrapChallengeRequest,
) (*authv1.BootstrapChallengeResponse, error) {
	if s.bootstrapFlow == nil {
		return nil, status.Error(codes.Internal, "bootstrap flow handler is required")
	}

	return s.bootstrapFlow.HandleBootstrapChallenge(
		ctx,
		req,
		buildExternalBootstrapChallengeRoutingInput(req),
		buildBootstrapChallengeInboundHeaders(req),
	)
}

func (s *AuthAuthorityExternalAuthRPCService) ForwardBootstrapAuthenticate(
	ctx context.Context,
	req *authv1.BootstrapAuthenticateRequest,
) (*authv1.BootstrapAuthenticateResponse, error) {
	if s.bootstrapFlow == nil {
		return nil, status.Error(codes.Internal, "bootstrap flow handler is required")
	}

	return s.bootstrapFlow.HandleBootstrapAuthenticate(
		ctx,
		req,
		buildExternalBootstrapAuthenticateRoutingInput(req),
		buildBootstrapAuthenticateInboundHeaders(req),
	)
}

func (s *AuthAuthorityExternalAuthRPCService) ensureInboundAccepted(
	ctx context.Context,
	route *communicationif.RoutingInput,
	headers map[string]string,
) error {
	decision, err := s.trafficStation.HandleInbound(
		ctx,
		&communicationif.InboundTrafficRequest{
			Route:   route,
			Headers: headers,
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

func buildUserPasswordRoutingInput(req *authv1.UserPasswordAuthRequest) *communicationif.RoutingInput {
	metadata := map[string]string{
		"grpc_service": externalAuthServiceName,
		"grpc_method":  "ForwardUserPassword",
		"operation":    "ForwardUserPassword",
	}
	if requestID := strings.TrimSpace(req.GetRequestId()); requestID != "" {
		metadata["request_id"] = requestID
	}
	if traceID := strings.TrimSpace(req.GetTraceId()); traceID != "" {
		metadata["trace_id"] = traceID
	}

	return &communicationif.RoutingInput{
		RouteKey:          externalAuthForwardRouteKey,
		Transport:         "grpc",
		Method:            "POST",
		Path:              authv1.AuthAuthorityExternalAuthService_ForwardUserPassword_FullMethodName,
		SourceService:     strings.TrimSpace(req.GetGatewayId()),
		TargetService:     "certification_server",
		TargetServiceHint: "certification_server",
		Metadata:          metadata,
	}
}

func buildUserPasswordHeaders(req *authv1.UserPasswordAuthRequest) map[string]string {
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

func buildExternalBootstrapChallengeRoutingInput(req *authv1.BootstrapChallengeRequest) *communicationif.RoutingInput {
	metadata := map[string]string{
		"grpc_service": externalAuthServiceName,
		"grpc_method":  "ForwardBootstrapChallenge",
		"operation":    "ForwardBootstrapChallenge",
	}
	if req != nil {
		if requestID := strings.TrimSpace(req.GetRequestId()); requestID != "" {
			metadata["request_id"] = requestID
		}
		if traceID := strings.TrimSpace(req.GetTraceId()); traceID != "" {
			metadata["trace_id"] = traceID
		}
	}

	return &communicationif.RoutingInput{
		RouteKey:          externalBootstrapChallengeRouteKey,
		Transport:         "grpc",
		Method:            "POST",
		Path:              authv1.AuthAuthorityExternalAuthService_ForwardBootstrapChallenge_FullMethodName,
		SourceService:     resolveExternalChallengeSourceService(req),
		TargetService:     "certification_server",
		TargetServiceHint: "certification_server",
		Metadata:          metadata,
	}
}

func buildExternalBootstrapAuthenticateRoutingInput(req *authv1.BootstrapAuthenticateRequest) *communicationif.RoutingInput {
	metadata := map[string]string{
		"grpc_service": externalAuthServiceName,
		"grpc_method":  "ForwardBootstrapAuthenticate",
		"operation":    "ForwardBootstrapAuthenticate",
	}
	if req != nil {
		if challenge := req.GetChallenge(); challenge != nil {
			if challengeID := strings.TrimSpace(challenge.GetChallengeId()); challengeID != "" {
				metadata["challenge_id"] = challengeID
			}
		}
	}

	return &communicationif.RoutingInput{
		RouteKey:          externalBootstrapAuthenticateRouteKey,
		Transport:         "grpc",
		Method:            "POST",
		Path:              authv1.AuthAuthorityExternalAuthService_ForwardBootstrapAuthenticate_FullMethodName,
		SourceService:     resolveAuthenticateSourceService(req),
		TargetService:     "certification_server",
		TargetServiceHint: "certification_server",
		Metadata:          metadata,
	}
}

func resolveExternalChallengeSourceService(req *authv1.BootstrapChallengeRequest) string {
	if req == nil {
		return "unknown_source"
	}
	if gatewayID := strings.TrimSpace(req.GetGatewayId()); gatewayID != "" {
		return gatewayID
	}
	return resolveChallengeSourceService(req)
}
