package rpcservice

import (
	"context"
	"strings"

	authv1 "certification_server/src/gen/auth/v1"
	communicationif "certification_server/src/iface/communication"
	orchestrationif "certification_server/src/iface/orchestration"
	modelsystem "certification_server/src/models/system"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// BootstrapFlowHandler 复用 bootstrap challenge/authenticate 的核心处理逻辑。
type BootstrapFlowHandler struct {
	orchestrator   orchestrationif.IAuthRequestOrchestrator
	trafficStation communicationif.ITrafficStation
}

func NewBootstrapFlowHandler(
	orchestrator orchestrationif.IAuthRequestOrchestrator,
	trafficStation communicationif.ITrafficStation,
) *BootstrapFlowHandler {
	return &BootstrapFlowHandler{
		orchestrator:   orchestrator,
		trafficStation: trafficStation,
	}
}

func (h *BootstrapFlowHandler) HandleBootstrapChallenge(
	ctx context.Context,
	req *authv1.BootstrapChallengeRequest,
	route *communicationif.RoutingInput,
	headers map[string]string,
) (*authv1.BootstrapChallengeResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "challenge request payload is required")
	}
	if h.orchestrator == nil || h.trafficStation == nil {
		return nil, status.Error(codes.Internal, modelsystem.ErrBootstrapRPCDependenciesRequired.Error())
	}
	if err := h.ensureInboundAccepted(ctx, route, headers); err != nil {
		return nil, err
	}

	challengeReq, err := mapProtoChallengeRequest(req)
	if err != nil {
		return nil, err
	}
	challenge, err := h.orchestrator.HandleBootstrapChallenge(ctx, challengeReq)
	if err != nil {
		return nil, MapAuthRPCError(err, codes.Internal, "init bootstrap challenge failed")
	}

	resp, err := buildChallengeResponse(challenge)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (h *BootstrapFlowHandler) HandleBootstrapAuthenticate(
	ctx context.Context,
	req *authv1.BootstrapAuthenticateRequest,
	route *communicationif.RoutingInput,
	headers map[string]string,
) (*authv1.BootstrapAuthenticateResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "bootstrap auth payload is required")
	}
	if h.orchestrator == nil || h.trafficStation == nil {
		return nil, status.Error(codes.Internal, modelsystem.ErrBootstrapRPCDependenciesRequired.Error())
	}
	if err := h.ensureInboundAccepted(ctx, route, headers); err != nil {
		return nil, err
	}

	authReq, err := mapProtoBootstrapAuthRequest(req)
	if err != nil {
		return nil, err
	}
	result, err := h.orchestrator.HandleBootstrapAuthenticate(ctx, authReq)
	if err != nil {
		return nil, MapAuthRPCError(err, codes.Internal, "authenticate bootstrap failed")
	}

	resp, err := buildBootstrapAuthResponse(result)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (h *BootstrapFlowHandler) ensureInboundAccepted(
	ctx context.Context,
	route *communicationif.RoutingInput,
	headers map[string]string,
) error {
	decision, err := h.trafficStation.HandleInbound(
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
