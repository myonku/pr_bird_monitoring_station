package orchestration

import (
	authif "certification_server/src/interfaces/auth"
	orchestrationif "certification_server/src/interfaces/orchestration"
	authmodel "certification_server/src/models/auth"
	commonmodel "certification_server/src/models/common"
	modelsystem "certification_server/src/models/system"
	"context"

	"github.com/google/uuid"
)

var _ orchestrationif.IAuthGatewayOrchestrator = (*AuthGatewayUsecase)(nil)

// AuthGatewayUsecase 统一编排认证中心所有鉴权能力，作为对外单一入口。
type AuthGatewayUsecase struct {
	Bootstrap       authif.IBootstrapService
	UserCredential  authif.IUserCredentialAuthService
	Token           authif.ITokenService
	Session         authif.ISessionService
	DownstreamGrant authif.IDownstreamGrantService
}

func (u *AuthGatewayUsecase) InitChallenge(
	ctx context.Context,
	req *authmodel.ChallengeRequest,
) (*authmodel.ChallengePayload, error) {
	if u == nil || u.Bootstrap == nil {
		return nil, &modelsystem.ErrAuthGatewayOrchestratorDepsRequired
	}
	return u.Bootstrap.InitChallenge(ctx, req)
}

func (u *AuthGatewayUsecase) AuthenticateBootstrap(
	ctx context.Context,
	req *authmodel.BootstrapAuthRequest,
) (*authmodel.BootstrapAuthResult, error) {
	if u == nil || u.Bootstrap == nil {
		return nil, &modelsystem.ErrAuthGatewayOrchestratorDepsRequired
	}
	return u.Bootstrap.AuthenticateBootstrap(ctx, req)
}

func (u *AuthGatewayUsecase) GetBootstrapStage(
	ctx context.Context,
	entityType commonmodel.EntityType,
	entityID string,
) (authmodel.BootstrapStage, error) {
	if u == nil || u.Bootstrap == nil {
		return "", &modelsystem.ErrAuthGatewayOrchestratorDepsRequired
	}
	return u.Bootstrap.GetBootstrapStage(ctx, entityType, entityID)
}

func (u *AuthGatewayUsecase) AuthenticateByPassword(
	ctx context.Context,
	req *authmodel.UserPasswordAuthRequest,
) (*authmodel.UserPasswordAuthResult, error) {
	if u == nil || u.UserCredential == nil {
		return nil, &modelsystem.ErrAuthGatewayOrchestratorDepsRequired
	}
	return u.UserCredential.AuthenticateByPassword(ctx, req)
}

func (u *AuthGatewayUsecase) RefreshModuleToken(
	ctx context.Context,
	req *authmodel.TokenRefreshRequest,
) (*authmodel.TokenBundle, error) {
	if u == nil || u.Token == nil {
		return nil, &modelsystem.ErrAuthGatewayOrchestratorDepsRequired
	}
	return u.Token.RefreshTokenBundle(ctx, req)
}

func (u *AuthGatewayUsecase) RefreshByUserSession(
	ctx context.Context,
	req *authmodel.TokenRefreshRequest,
) (*authmodel.TokenBundle, error) {
	if u == nil || u.UserCredential == nil {
		return nil, &modelsystem.ErrAuthGatewayOrchestratorDepsRequired
	}
	return u.UserCredential.RefreshByUserSession(ctx, req)
}

func (u *AuthGatewayUsecase) VerifyToken(
	ctx context.Context,
	req *authmodel.TokenVerifyRequest,
) (*authmodel.TokenVerificationResult, error) {
	if u == nil || u.Token == nil {
		return nil, &modelsystem.ErrAuthGatewayOrchestratorDepsRequired
	}
	return u.Token.VerifyToken(ctx, req)
}

func (u *AuthGatewayUsecase) RevokeToken(
	ctx context.Context,
	req *authmodel.TokenRevokeRequest,
) error {
	if u == nil || u.Token == nil {
		return &modelsystem.ErrAuthGatewayOrchestratorDepsRequired
	}
	return u.Token.RevokeToken(ctx, req)
}

func (u *AuthGatewayUsecase) RevokeUserSession(
	ctx context.Context,
	req *authmodel.SessionRevokeRequest,
) error {
	if u == nil || u.UserCredential == nil {
		return &modelsystem.ErrAuthGatewayOrchestratorDepsRequired
	}
	return u.UserCredential.RevokeUserSession(ctx, req)
}

func (u *AuthGatewayUsecase) RevokeModuleSession(
	ctx context.Context,
	req *authmodel.SessionRevokeRequest,
) error {
	if u == nil || u.Session == nil {
		return &modelsystem.ErrAuthGatewayOrchestratorDepsRequired
	}

	var familyID uuid.UUID
	if req != nil && req.SessionID != uuid.Nil {
		session, err := u.Session.GetSession(ctx, req.SessionID.String())
		if err == nil && session != nil {
			familyID = session.TokenFamilyID
		}
	}

	if err := u.Session.RevokeSession(ctx, req); err != nil {
		return err
	}

	if u.Token != nil && familyID != uuid.Nil {
		return u.Token.RevokeTokenFamily(ctx, familyID.String(), req.RevokedBy)
	}

	return nil
}

func (u *AuthGatewayUsecase) ValidateSession(
	ctx context.Context,
	req *authmodel.SessionValidateRequest,
) (*authmodel.Session, error) {
	if u == nil || u.Session == nil {
		return nil, &modelsystem.ErrAuthGatewayOrchestratorDepsRequired
	}
	return u.Session.ValidateSession(ctx, req)
}

func (u *AuthGatewayUsecase) IssueDownstreamGrant(
	ctx context.Context,
	req *authmodel.DownstreamGrantRequest,
) (*authmodel.DownstreamAccessGrant, error) {
	if u == nil || u.DownstreamGrant == nil {
		return nil, &modelsystem.ErrAuthGatewayOrchestratorDepsRequired
	}
	return u.DownstreamGrant.IssueDownstreamGrant(ctx, req)
}
