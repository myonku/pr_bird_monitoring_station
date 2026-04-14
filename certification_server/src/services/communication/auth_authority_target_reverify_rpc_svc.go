package communication

import (
	"context"
	"strings"
	"time"

	authv1 "certification_server/src/gen/auth/v1"
	commonif "certification_server/src/iface/common"
	communicationif "certification_server/src/iface/communication"
	orchestrationif "certification_server/src/iface/orchestration"
	authmodel "certification_server/src/models/auth"
	modelsystem "certification_server/src/models/system"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const targetReverifyServiceName = "bms.auth.v1.AuthAuthorityTargetReverifyService"

// AuthAuthorityTargetReverifyRPCService 提供认证中心 target_reverify 最小 RPC 服务。
type AuthAuthorityTargetReverifyRPCService struct {
	authv1.UnimplementedAuthAuthorityTargetReverifyServiceServer

	orchestrator   orchestrationif.IAuthRequestOrchestrator
	trafficStation communicationif.ITrafficStation
}

func NewAuthAuthorityTargetReverifyRPCService(
	orchestrator orchestrationif.IAuthRequestOrchestrator,
	trafficStation communicationif.ITrafficStation,
) *AuthAuthorityTargetReverifyRPCService {
	return &AuthAuthorityTargetReverifyRPCService{
		orchestrator:   orchestrator,
		trafficStation: trafficStation,
	}
}

// RegisterAuthAuthorityTargetReverifyRPC 将 target_reverify gRPC 服务注册到认证中心。
func RegisterAuthAuthorityTargetReverifyRPC(
	server *grpc.Server,
	orchestrator orchestrationif.IAuthRequestOrchestrator,
	trafficStation communicationif.ITrafficStation,
) {
	if server == nil {
		return
	}
	authv1.RegisterAuthAuthorityTargetReverifyServiceServer(
		server,
		NewAuthAuthorityTargetReverifyRPCService(orchestrator, trafficStation),
	)
}

func (s *AuthAuthorityTargetReverifyRPCService) ReverifyForwardedContext(
	ctx context.Context,
	req *authv1.ForwardedAuthContext,
) (*authv1.ForwardedAuthVerificationResult, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "forwarded auth context is required")
	}
	if s.orchestrator == nil || s.trafficStation == nil {
		return nil, status.Error(codes.Internal, modelsystem.ErrBootstrapRPCDependenciesRequired.Error())
	}

	if err := s.ensureInboundAccepted(
		ctx,
		buildTargetReverifyRoutingInput(req),
		buildTargetReverifyHeaders(req),
	); err != nil {
		return nil, err
	}

	if grantIssued := req.GetGrantIssuedAtMs(); grantIssued > 0 {
		if grantExpires := req.GetGrantExpiresAtMs(); grantExpires > 0 && grantIssued > grantExpires {
			return &authv1.ForwardedAuthVerificationResult{
				Allowed:       false,
				FailureReason: "grant issued/expires window is invalid",
			}, nil
		}
	}
	if grantExpires := req.GetGrantExpiresAtMs(); grantExpires > 0 && time.Now().UnixMilli() > grantExpires {
		return &authv1.ForwardedAuthVerificationResult{
			Allowed:       false,
			FailureReason: "grant expired",
		}, nil
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
			RequireActive: true,
			MinVersion:    0,
		},
	)
	if err != nil {
		return &authv1.ForwardedAuthVerificationResult{
			Allowed:       false,
			FailureReason: strings.TrimSpace(err.Error()),
		}, nil
	}

	tokenID := uuid.Nil
	if rawTokenID := strings.TrimSpace(req.GetTokenId()); rawTokenID != "" {
		parsed, parseErr := uuid.Parse(rawTokenID)
		if parseErr != nil {
			return &authv1.ForwardedAuthVerificationResult{
				Allowed:       false,
				FailureReason: "invalid token_id",
			}, nil
		}
		tokenID = parsed
	}

	identity := &authmodel.IdentityContext{
		Principal:     session.Principal,
		EntityType:    session.EntityType,
		EntityID:      session.EntityID,
		PrincipalID:   session.PrincipalID,
		SessionID:     session.ID,
		TokenID:       tokenID,
		TokenFamilyID: session.TokenFamilyID,
		TokenType:     authmodel.TokenDownstream,
		Role:          strings.TrimSpace(session.RoleSnapshot),
		Scopes:        append([]string(nil), session.ScopeSnapshot...),
		AuthMethod:    session.AuthMethod,
		ClientID:      strings.TrimSpace(session.ClientID),
		GatewayID:     strings.TrimSpace(req.GetGatewayId()),
		SourceService: strings.TrimSpace(req.GetSourceService()),
		TargetService: strings.TrimSpace(req.GetTargetService()),
		RequestID:     strings.TrimSpace(req.GetRequestId()),
		TraceID:       strings.TrimSpace(req.GetTraceId()),
		IssuedAt:      session.CreatedAt,
		ExpiresAt:     session.ExpiresAt,
	}

	return &authv1.ForwardedAuthVerificationResult{
		Allowed:       true,
		Identity:      buildIdentityProto(identity),
		Session:       buildSessionProto(session),
		FailureReason: "",
	}, nil
}

func (s *AuthAuthorityTargetReverifyRPCService) ensureInboundAccepted(
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

func buildTargetReverifyRoutingInput(req *authv1.ForwardedAuthContext) *communicationif.RoutingInput {
	metadata := map[string]string{
		"grpc_service": targetReverifyServiceName,
		"grpc_method":  "ReverifyForwardedContext",
		"operation":    "ReverifyForwardedContext",
	}
	if requestID := strings.TrimSpace(req.GetRequestId()); requestID != "" {
		metadata["request_id"] = requestID
	}
	if traceID := strings.TrimSpace(req.GetTraceId()); traceID != "" {
		metadata["trace_id"] = traceID
	}
	if principalID := strings.TrimSpace(req.GetPrincipalId()); principalID != "" {
		metadata["principal_id"] = principalID
	}

	return &communicationif.RoutingInput{
		RouteKey:          targetReverifyRouteKey,
		Transport:         "grpc",
		Method:            "POST",
		Path:              authv1.AuthAuthorityTargetReverifyService_ReverifyForwardedContext_FullMethodName,
		SourceService:     strings.TrimSpace(req.GetSourceService()),
		TargetService:     "certification_server",
		TargetServiceHint: "certification_server",
		Metadata:          metadata,
	}
}

func buildTargetReverifyHeaders(req *authv1.ForwardedAuthContext) map[string]string {
	headers := map[string]string{}
	if principalID := strings.TrimSpace(req.GetPrincipalId()); principalID != "" {
		headers["x-downstream-principal"] = principalID
	}
	if sessionID := strings.TrimSpace(req.GetSessionId()); sessionID != "" {
		headers["x-downstream-session-id"] = sessionID
	}
	if tokenID := strings.TrimSpace(req.GetTokenId()); tokenID != "" {
		headers["x-downstream-token-id"] = tokenID
	}
	if requestID := strings.TrimSpace(req.GetRequestId()); requestID != "" {
		headers["x-request-id"] = requestID
	}
	if traceID := strings.TrimSpace(req.GetTraceId()); traceID != "" {
		headers["x-trace-id"] = traceID
	}
	return headers
}
