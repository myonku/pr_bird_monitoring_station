package auth

import (
	"context"

	authif "gateway/src/interfaces/auth"
	authmodel "gateway/src/models/auth"
	modelsystem "gateway/src/models/system"
)

var _ authif.IUserCredentialAuthClient = (*ForwardUserCredentialAuthClient)(nil)

// ForwardUserCredentialAuthClient 把用户认证相关请求统一转发给认证中心。
type ForwardUserCredentialAuthClient struct {
	Authority authif.IAuthGatewayAuthorityClient
}

func NewForwardUserCredentialAuthClient(authority authif.IAuthGatewayAuthorityClient) *ForwardUserCredentialAuthClient {
	return &ForwardUserCredentialAuthClient{Authority: authority}
}

func (c *ForwardUserCredentialAuthClient) AuthenticateByPassword(
	ctx context.Context,
	req *authmodel.UserPasswordAuthRequest,
) (*authmodel.UserPasswordAuthResult, error) {
	if c == nil || c.Authority == nil {
		return nil, &modelsystem.ErrUserAuthClientNotConfigured
	}
	return c.Authority.AuthenticateByPassword(ctx, req)
}

func (c *ForwardUserCredentialAuthClient) RefreshByUserSession(
	ctx context.Context,
	req *authmodel.TokenRefreshRequest,
) (*authmodel.TokenBundle, error) {
	if c == nil || c.Authority == nil {
		return nil, &modelsystem.ErrUserAuthClientNotConfigured
	}
	return c.Authority.RefreshByUserSession(ctx, req)
}

func (c *ForwardUserCredentialAuthClient) VerifyUserToken(
	ctx context.Context,
	req *authmodel.TokenVerifyRequest,
) (*authmodel.TokenVerificationResult, error) {
	if c == nil || c.Authority == nil {
		return nil, &modelsystem.ErrUserAuthClientNotConfigured
	}
	return c.Authority.VerifyToken(ctx, req)
}

func (c *ForwardUserCredentialAuthClient) RevokeUserToken(
	ctx context.Context,
	req *authmodel.TokenRevokeRequest,
) error {
	if c == nil || c.Authority == nil {
		return &modelsystem.ErrUserAuthClientNotConfigured
	}
	return c.Authority.RevokeToken(ctx, req)
}

func (c *ForwardUserCredentialAuthClient) RevokeUserSession(
	ctx context.Context,
	req *authmodel.SessionRevokeRequest,
) error {
	if c == nil || c.Authority == nil {
		return &modelsystem.ErrUserAuthClientNotConfigured
	}
	return c.Authority.RevokeUserSession(ctx, req)
}
