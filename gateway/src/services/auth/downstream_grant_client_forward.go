package auth

import (
	"context"

	authif "gateway/src/interfaces/auth"
	authmodel "gateway/src/models/auth"
	modelsystem "gateway/src/models/system"
)

var _ authif.IDownstreamGrantClient = (*ForwardDownstreamGrantClient)(nil)

// ForwardDownstreamGrantClient 将下游授权签发请求转发给认证中心。
type ForwardDownstreamGrantClient struct {
	Authority authif.IAuthAuthorityClient
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
	return c.Authority.IssueDownstreamGrant(ctx, req)
}
