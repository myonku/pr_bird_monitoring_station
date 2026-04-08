package auth

import (
	"context"
	authmodel "gateway/src/models/auth"
)

// IDownstreamGrantClient 定义网关申请下游授权的客户端接口。
type IDownstreamGrantClient interface {
	IssueDownstreamGrant(ctx context.Context, req *authmodel.DownstreamGrantRequest) (*authmodel.DownstreamAccessGrant, error)
}
