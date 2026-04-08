package auth

import (
	"context"

	authif "gateway/src/iface/auth"
	authmodel "gateway/src/models/auth"
	modelsystem "gateway/src/models/system"
)

var _ authif.IDownstreamGrantClient = (*ForwardDownstreamGrantClient)(nil)

// ForwardDownstreamGrantClient 将下游授权签发请求转发给认证中心。
type ForwardDownstreamGrantClient struct {
	Authority         authif.IAuthAuthorityClient
	ModuleCredentials authif.IModuleCredentialManager
}

func NewForwardDownstreamGrantClient(authority authif.IAuthAuthorityClient) *ForwardDownstreamGrantClient {
	return &ForwardDownstreamGrantClient{Authority: authority}
}

func (c *ForwardDownstreamGrantClient) IssueDownstreamGrant(
	ctx context.Context,
	req *authmodel.DownstreamGrantRequest,
) (*authmodel.DownstreamAccessGrant, error) {
	if c == nil || c.Authority == nil {
		return nil, &modelsystem.ErrDownstreamGrantClientRequired
	}
	if req == nil {
		return nil, &modelsystem.ErrDownstreamGrantRequestNil
	}

	forwardReq := cloneGrantRequest(req)
	if forwardReq.Identity.PrincipalID == "" && c.ModuleCredentials != nil {
		credentials, err := c.ModuleCredentials.EnsureActive(ctx)
		if err != nil {
			return nil, err
		}
		if credentials != nil && credentials.Identity != nil {
			forwardReq.Identity = *cloneIdentity(credentials.Identity)
			if forwardReq.Identity.SourceService == "" {
				forwardReq.Identity.SourceService = forwardReq.Identity.EntityID
			}
			if forwardReq.Identity.GatewayID == "" {
				forwardReq.Identity.GatewayID = forwardReq.Identity.EntityID
			}
		}
	}

	return c.Authority.IssueDownstreamGrant(ctx, forwardReq)
}

func cloneGrantRequest(req *authmodel.DownstreamGrantRequest) *authmodel.DownstreamGrantRequest {
	if req == nil {
		return nil
	}
	out := *req
	out.Identity = *cloneIdentity(&req.Identity)
	return &out
}

func cloneIdentity(identity *authmodel.IdentityContext) *authmodel.IdentityContext {
	if identity == nil {
		return &authmodel.IdentityContext{}
	}
	out := *identity
	out.Scopes = append([]string(nil), identity.Scopes...)
	return &out
}
