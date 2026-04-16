package orchestration

import (
	"context"

	commonif "certification_server/src/iface/common"
	authmodel "certification_server/src/models/auth"
	modelsystem "certification_server/src/models/system"
)

func (s *AuthRequestOrchestratorService) HandleTokenVerify(
	ctx context.Context, req *commonif.TokenVerifyRequest,
) (*authmodel.TokenVerificationResult, error) {
	if req == nil {
		return nil, &modelsystem.ErrRawTokenRequired
	}
	if s.tokenManager == nil {
		return nil, &modelsystem.ErrBootstrapDepsNotReady
	}
	return s.tokenManager.VerifyToken(ctx, req)
}

func (s *AuthRequestOrchestratorService) HandleSessionValidate(
	ctx context.Context, req *commonif.SessionValidateRequest,
) (*authmodel.Session, error) {
	if req == nil {
		return nil, &modelsystem.ErrSessionValidateRequestNil
	}
	if s.sessionManager == nil {
		return nil, &modelsystem.ErrBootstrapDepsNotReady
	}
	return s.sessionManager.ValidateSession(ctx, req)
}

func (s *AuthRequestOrchestratorService) HandleTokenRefresh(
	ctx context.Context, req *commonif.TokenRefreshRequest,
) (*authmodel.TokenBundle, error) {
	if req == nil {
		return nil, &modelsystem.ErrRefreshTokenRequired
	}
	if s.tokenManager == nil {
		return nil, &modelsystem.ErrBootstrapDepsNotReady
	}
	return s.tokenManager.RefreshTokenBundle(ctx, req)
}

func (s *AuthRequestOrchestratorService) HandleTokenRevoke(
	ctx context.Context, req *commonif.TokenRevokeRequest,
) error {
	if req == nil {
		return &modelsystem.ErrTokenRevokeRequestNil
	}
	if s.tokenManager == nil {
		return &modelsystem.ErrBootstrapDepsNotReady
	}
	return s.tokenManager.RevokeToken(ctx, req)
}
