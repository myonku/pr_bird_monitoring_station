package grpcadapter

import (
	orchestrationif "certification_server/src/interfaces/orchestration"
	authmodel "certification_server/src/models/auth"
	commonmodel "certification_server/src/models/common"
	modelsystem "certification_server/src/models/system"
	"context"
)

// AuthGatewayHandler 提供认证中心统一鉴权门面的 gRPC handler 骨架。
// 当前阶段先固定 handler 与 orchestration 对接边界，协议绑定后续补齐。
type AuthGatewayHandler struct {
	Orchestrator orchestrationif.IAuthGatewayOrchestrator
}

func NewAuthGatewayHandler(orchestrator orchestrationif.IAuthGatewayOrchestrator) *AuthGatewayHandler {
	return &AuthGatewayHandler{Orchestrator: orchestrator}
}

func (h *AuthGatewayHandler) InitChallenge(
	ctx context.Context,
	req *authmodel.ChallengeRequest,
) (*authmodel.ChallengePayload, error) {
	if h == nil || h.Orchestrator == nil {
		return nil, &modelsystem.ErrAuthGatewayOrchestratorDepsRequired
	}
	return h.Orchestrator.InitChallenge(ctx, req)
}

func (h *AuthGatewayHandler) AuthenticateBootstrap(
	ctx context.Context,
	req *authmodel.BootstrapAuthRequest,
) (*authmodel.BootstrapAuthResult, error) {
	if h == nil || h.Orchestrator == nil {
		return nil, &modelsystem.ErrAuthGatewayOrchestratorDepsRequired
	}
	return h.Orchestrator.AuthenticateBootstrap(ctx, req)
}

func (h *AuthGatewayHandler) GetBootstrapStage(
	ctx context.Context,
	entityType commonmodel.EntityType,
	entityID string,
) (authmodel.BootstrapStage, error) {
	if h == nil || h.Orchestrator == nil {
		return "", &modelsystem.ErrAuthGatewayOrchestratorDepsRequired
	}
	return h.Orchestrator.GetBootstrapStage(ctx, entityType, entityID)
}

func (h *AuthGatewayHandler) AuthenticateByPassword(
	ctx context.Context,
	req *authmodel.UserPasswordAuthRequest,
) (*authmodel.UserPasswordAuthResult, error) {
	if h == nil || h.Orchestrator == nil {
		return nil, &modelsystem.ErrAuthGatewayOrchestratorDepsRequired
	}
	return h.Orchestrator.AuthenticateByPassword(ctx, req)
}

func (h *AuthGatewayHandler) RefreshByUserSession(
	ctx context.Context,
	req *authmodel.TokenRefreshRequest,
) (*authmodel.TokenBundle, error) {
	if h == nil || h.Orchestrator == nil {
		return nil, &modelsystem.ErrAuthGatewayOrchestratorDepsRequired
	}
	return h.Orchestrator.RefreshByUserSession(ctx, req)
}

func (h *AuthGatewayHandler) VerifyToken(
	ctx context.Context,
	req *authmodel.TokenVerifyRequest,
) (*authmodel.TokenVerificationResult, error) {
	if h == nil || h.Orchestrator == nil {
		return nil, &modelsystem.ErrAuthGatewayOrchestratorDepsRequired
	}
	return h.Orchestrator.VerifyToken(ctx, req)
}

func (h *AuthGatewayHandler) RevokeToken(
	ctx context.Context,
	req *authmodel.TokenRevokeRequest,
) error {
	if h == nil || h.Orchestrator == nil {
		return &modelsystem.ErrAuthGatewayOrchestratorDepsRequired
	}
	return h.Orchestrator.RevokeToken(ctx, req)
}

func (h *AuthGatewayHandler) RevokeUserSession(
	ctx context.Context,
	req *authmodel.SessionRevokeRequest,
) error {
	if h == nil || h.Orchestrator == nil {
		return &modelsystem.ErrAuthGatewayOrchestratorDepsRequired
	}
	return h.Orchestrator.RevokeUserSession(ctx, req)
}

func (h *AuthGatewayHandler) ValidateSession(
	ctx context.Context,
	req *authmodel.SessionValidateRequest,
) (*authmodel.Session, error) {
	if h == nil || h.Orchestrator == nil {
		return nil, &modelsystem.ErrAuthGatewayOrchestratorDepsRequired
	}
	return h.Orchestrator.ValidateSession(ctx, req)
}

func (h *AuthGatewayHandler) IssueDownstreamGrant(
	ctx context.Context,
	req *authmodel.DownstreamGrantRequest,
) (*authmodel.DownstreamAccessGrant, error) {
	if h == nil || h.Orchestrator == nil {
		return nil, &modelsystem.ErrAuthGatewayOrchestratorDepsRequired
	}
	return h.Orchestrator.IssueDownstreamGrant(ctx, req)
}
