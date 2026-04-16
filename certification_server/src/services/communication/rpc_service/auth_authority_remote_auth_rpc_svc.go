package rpcservice

import (
	"context"
	"strings"

	authv1 "certification_server/src/gen/auth/v1"
	commonif "certification_server/src/iface/common"
	communicationif "certification_server/src/iface/communication"
	orchestrationif "certification_server/src/iface/orchestration"
	authmodel "certification_server/src/models/auth"
	modelsystem "certification_server/src/models/system"
	communication "certification_server/src/services/communication"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const remoteAuthServiceName = "bms.auth.v1.AuthAuthorityRemoteAuthService"

// AuthAuthorityRemoteAuthRPCService 提供认证中心 remote_auth 最小 RPC 服务。
type AuthAuthorityRemoteAuthRPCService struct {
	authv1.UnimplementedAuthAuthorityRemoteAuthServiceServer

	orchestrator   orchestrationif.IAuthRequestOrchestrator
	trafficStation communicationif.ITrafficStation
}

func NewAuthAuthorityRemoteAuthRPCService(
	orchestrator orchestrationif.IAuthRequestOrchestrator,
	trafficStation communicationif.ITrafficStation,
) *AuthAuthorityRemoteAuthRPCService {
	return &AuthAuthorityRemoteAuthRPCService{
		orchestrator:   orchestrator,
		trafficStation: trafficStation,
	}
}

// RegisterAuthAuthorityRemoteAuthRPC 将 remote_auth gRPC 服务注册到认证中心。
func RegisterAuthAuthorityRemoteAuthRPC(
	server *grpc.Server,
	orchestrator orchestrationif.IAuthRequestOrchestrator,
	trafficStation communicationif.ITrafficStation,
) {
	if server == nil {
		return
	}
	authv1.RegisterAuthAuthorityRemoteAuthServiceServer(
		server,
		NewAuthAuthorityRemoteAuthRPCService(orchestrator, trafficStation),
	)
}

func (s *AuthAuthorityRemoteAuthRPCService) VerifyToken(
	ctx context.Context,
	req *authv1.TokenVerifyRequest,
) (*authv1.TokenVerificationResult, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "verify token payload is required")
	}
	if s.orchestrator == nil || s.trafficStation == nil {
		return nil, status.Error(codes.Internal, modelsystem.ErrBootstrapRPCDependenciesRequired.Error())
	}
	if strings.TrimSpace(req.GetRawToken()) == "" {
		return nil, status.Error(codes.InvalidArgument, modelsystem.ErrRawTokenRequired.Error())
	}

	if err := s.ensureInboundAccepted(
		ctx,
		buildVerifyTokenRoutingInput(req),
		buildVerifyTokenHeaders(req),
	); err != nil {
		return nil, err
	}

	result, err := s.orchestrator.HandleTokenVerify(
		ctx,
		&commonif.TokenVerifyRequest{
			RawToken:            strings.TrimSpace(req.GetRawToken()),
			ExpectedTypes:       mapProtoExpectedTokenTypes(req.GetExpectedTypes()),
			ExpectedAudience:    strings.TrimSpace(req.GetExpectedAudience()),
			RequireScopes:       append([]string(nil), req.GetRequireScopes()...),
			SourceService:       strings.TrimSpace(req.GetSourceService()),
			TargetService:       strings.TrimSpace(req.GetTargetService()),
			AllowExpiredSkewSec: req.GetAllowExpiredSkewSec(),
		},
	)
	if err != nil {
		return nil, MapAuthRPCError(err, codes.Internal, "verify token failed")
	}

	return buildTokenVerificationProto(result), nil
}

func (s *AuthAuthorityRemoteAuthRPCService) ValidateSession(
	ctx context.Context,
	req *authv1.SessionValidateRequest,
) (*authv1.Session, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "validate session payload is required")
	}
	if s.orchestrator == nil || s.trafficStation == nil {
		return nil, status.Error(codes.Internal, modelsystem.ErrBootstrapRPCDependenciesRequired.Error())
	}

	if err := s.ensureInboundAccepted(
		ctx,
		buildValidateSessionRoutingInput(req),
		buildValidateSessionHeaders(req),
	); err != nil {
		return nil, err
	}

	sessionID, err := uuid.Parse(strings.TrimSpace(req.GetSessionId()))
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid session_id: %v", err)
	}

	session, err := s.orchestrator.HandleSessionValidate(
		ctx,
		&commonif.SessionValidateRequest{
			SessionID:     sessionID,
			PrincipalID:   strings.TrimSpace(req.GetPrincipalId()),
			RequireActive: req.GetRequireActive(),
			MinVersion:    req.GetMinVersion(),
		},
	)
	if err != nil {
		return nil, MapAuthRPCError(err, codes.Internal, "validate session failed")
	}

	return buildSessionProto(session), nil
}

func (s *AuthAuthorityRemoteAuthRPCService) ensureInboundAccepted(
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
		return MapAuthRPCError(err, codes.Internal, "inbound traffic station failed")
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

func buildVerifyTokenRoutingInput(req *authv1.TokenVerifyRequest) *communicationif.RoutingInput {
	metadata := map[string]string{
		"grpc_service": remoteAuthServiceName,
		"grpc_method":  "VerifyToken",
		"operation":    "VerifyToken",
	}
	if source := strings.TrimSpace(req.GetSourceService()); source != "" {
		metadata["source_service"] = source
	}
	if target := strings.TrimSpace(req.GetTargetService()); target != "" {
		metadata["target_service"] = target
	}

	return &communicationif.RoutingInput{
		RouteKey:          communication.RemoteAuthVerifyRouteKey,
		Transport:         "grpc",
		Method:            "POST",
		Path:              authv1.AuthAuthorityRemoteAuthService_VerifyToken_FullMethodName,
		SourceService:     strings.TrimSpace(req.GetSourceService()),
		TargetService:     "certification_server",
		TargetServiceHint: "certification_server",
		Metadata:          metadata,
	}
}

func buildValidateSessionRoutingInput(req *authv1.SessionValidateRequest) *communicationif.RoutingInput {
	metadata := map[string]string{
		"grpc_service": remoteAuthServiceName,
		"grpc_method":  "ValidateSession",
		"operation":    "ValidateSession",
	}
	if principalID := strings.TrimSpace(req.GetPrincipalId()); principalID != "" {
		metadata["principal_id"] = principalID
	}
	if sessionID := strings.TrimSpace(req.GetSessionId()); sessionID != "" {
		metadata["session_id"] = sessionID
	}

	return &communicationif.RoutingInput{
		RouteKey:          communication.RemoteSessionValidateRouteKey,
		Transport:         "grpc",
		Method:            "POST",
		Path:              authv1.AuthAuthorityRemoteAuthService_ValidateSession_FullMethodName,
		SourceService:     strings.TrimSpace(req.GetPrincipalId()),
		TargetService:     "certification_server",
		TargetServiceHint: "certification_server",
		Metadata:          metadata,
	}
}

func buildVerifyTokenHeaders(req *authv1.TokenVerifyRequest) map[string]string {
	headers := map[string]string{}
	if source := strings.TrimSpace(req.GetSourceService()); source != "" {
		headers["x-source-service"] = source
	}
	if target := strings.TrimSpace(req.GetTargetService()); target != "" {
		headers["x-target-service"] = target
	}
	return headers
}

func buildValidateSessionHeaders(req *authv1.SessionValidateRequest) map[string]string {
	headers := map[string]string{}
	if principalID := strings.TrimSpace(req.GetPrincipalId()); principalID != "" {
		headers["x-principal-id"] = principalID
	}
	if sessionID := strings.TrimSpace(req.GetSessionId()); sessionID != "" {
		headers["x-session-id"] = sessionID
	}
	return headers
}

func mapProtoExpectedTokenTypes(raw []authv1.TokenType) []authmodel.TokenType {
	if len(raw) == 0 {
		return nil
	}

	out := make([]authmodel.TokenType, 0, len(raw))
	for _, item := range raw {
		switch item {
		case authv1.TokenType_TOKEN_TYPE_ACCESS:
			out = append(out, authmodel.TokenAccess)
		case authv1.TokenType_TOKEN_TYPE_REFRESH:
			out = append(out, authmodel.TokenRefresh)
		case authv1.TokenType_TOKEN_TYPE_SERVICE:
			out = append(out, authmodel.TokenService)
		case authv1.TokenType_TOKEN_TYPE_DOWNSTREAM:
			out = append(out, authmodel.TokenDownstream)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
