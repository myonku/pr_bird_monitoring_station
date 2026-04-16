package communication

import (
	"context"
	"strings"

	authv1 "certification_server/src/gen/auth/v1"
	commonif "certification_server/src/iface/common"
	communicationif "certification_server/src/iface/communication"
	orchestrationif "certification_server/src/iface/orchestration"
	modelsystem "certification_server/src/models/system"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const tokenRefreshServiceName = "bms.auth.v1.AuthAuthorityTokenRefreshService"

// AuthAuthorityTokenRefreshRPCService 提供认证中心 backend token refresh 最小 RPC 服务。
type AuthAuthorityTokenRefreshRPCService struct {
	authv1.UnimplementedAuthAuthorityTokenRefreshServiceServer

	orchestrator   orchestrationif.IAuthRequestOrchestrator
	trafficStation communicationif.ITrafficStation
}

func NewAuthAuthorityTokenRefreshRPCService(
	orchestrator orchestrationif.IAuthRequestOrchestrator,
	trafficStation communicationif.ITrafficStation,
) *AuthAuthorityTokenRefreshRPCService {
	return &AuthAuthorityTokenRefreshRPCService{
		orchestrator:   orchestrator,
		trafficStation: trafficStation,
	}
}

// RegisterAuthAuthorityTokenRefreshRPC 将 token_refresh gRPC 服务注册到认证中心。
func RegisterAuthAuthorityTokenRefreshRPC(
	server *grpc.Server,
	orchestrator orchestrationif.IAuthRequestOrchestrator,
	trafficStation communicationif.ITrafficStation,
) {
	if server == nil {
		return
	}
	authv1.RegisterAuthAuthorityTokenRefreshServiceServer(
		server,
		NewAuthAuthorityTokenRefreshRPCService(orchestrator, trafficStation),
	)
}

func (s *AuthAuthorityTokenRefreshRPCService) RefreshTokenBundle(
	ctx context.Context,
	req *authv1.TokenRefreshRequest,
) (*authv1.TokenBundle, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "token refresh payload is required")
	}
	if s.orchestrator == nil || s.trafficStation == nil {
		return nil, status.Error(codes.Internal, modelsystem.ErrBootstrapRPCDependenciesRequired.Error())
	}

	if err := s.ensureInboundAccepted(
		ctx,
		buildTokenRefreshRoutingInput(req),
		buildTokenRefreshHeaders(req),
	); err != nil {
		return nil, err
	}

	result, err := s.orchestrator.HandleTokenRefresh(
		ctx,
		&commonif.TokenRefreshRequest{
			RefreshToken: strings.TrimSpace(req.GetRefreshToken()),
			ClientID:     strings.TrimSpace(req.GetClientId()),
			GatewayID:    strings.TrimSpace(req.GetGatewayId()),
			SourceIP:     strings.TrimSpace(req.GetSourceIp()),
			UserAgent:    strings.TrimSpace(req.GetUserAgent()),
			RequestID:    strings.TrimSpace(req.GetRequestId()),
			TraceID:      strings.TrimSpace(req.GetTraceId()),
		},
	)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "token refresh failed: %v", err)
	}
	if result == nil {
		return nil, status.Error(codes.Internal, "token refresh result is nil")
	}

	return buildTokenBundleProto(*result), nil
}

func (s *AuthAuthorityTokenRefreshRPCService) ensureInboundAccepted(
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

func buildTokenRefreshRoutingInput(req *authv1.TokenRefreshRequest) *communicationif.RoutingInput {
	metadata := map[string]string{
		"grpc_service": tokenRefreshServiceName,
		"grpc_method":  "RefreshTokenBundle",
		"operation":    "RefreshTokenBundle",
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
		RouteKey:          moduleTokenRefreshRouteKey,
		Transport:         "grpc",
		Method:            "POST",
		Path:              authv1.AuthAuthorityTokenRefreshService_RefreshTokenBundle_FullMethodName,
		SourceService:     resolveRefreshSourceService(req),
		TargetService:     "certification_server",
		TargetServiceHint: "certification_server",
		Metadata:          metadata,
	}
}
