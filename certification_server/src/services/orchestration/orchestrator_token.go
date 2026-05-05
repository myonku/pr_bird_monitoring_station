package orchestration

import (
	"context"

	commonif "certification_server/src/iface/common"
	authmodel "certification_server/src/models/auth"
	modelsystem "certification_server/src/models/system"
)

func (s *AuthRequestOrchestratorService) HandleTokenVerify(
	ctx context.Context, req *commonif.TokenVerifyRequest,
) (out *authmodel.TokenVerificationResult, err error) {
	logAuthRequestObservation("auth.token.verify")
	defer func() {
		if err != nil {
			logAuthRequestResult("auth.token.verify", false, err.Error())
		} else if out != nil {
			logAuthRequestResult("auth.token.verify", true, "")
		} else {
			logAuthRequestResult("auth.token.verify", true, "")
		}
	}()
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
) (out *authmodel.Session, err error) {
	logAuthRequestObservation("auth.session.validate")
	defer func() {
		if err != nil {
			logAuthRequestResult("auth.session.validate", false, err.Error())
		} else if out != nil {
			logAuthRequestResult("auth.session.validate", true, "session_id="+out.ID.String())
		} else {
			logAuthRequestResult("auth.session.validate", true, "")
		}
	}()
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
) (out *authmodel.TokenBundle, err error) {
	logAuthRequestObservation("auth.token.refresh")
	defer func() {
		if err != nil {
			logAuthRequestResult("auth.token.refresh", false, err.Error())
		} else if out != nil {
			logAuthRequestResult("auth.token.refresh", true, "")
		} else {
			logAuthRequestResult("auth.token.refresh", true, "")
		}
	}()
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
) (err error) {
	logAuthRequestObservation("auth.token.revoke")
	defer func() {
		if err != nil {
			logAuthRequestResult("auth.token.revoke", false, err.Error())
		} else {
			logAuthRequestResult("auth.token.revoke", true, "")
		}
	}()
	if req == nil {
		return &modelsystem.ErrTokenRevokeRequestNil
	}
	if s.tokenManager == nil {
		return &modelsystem.ErrBootstrapDepsNotReady
	}
	err = s.tokenManager.RevokeToken(ctx, req)
	return
}
