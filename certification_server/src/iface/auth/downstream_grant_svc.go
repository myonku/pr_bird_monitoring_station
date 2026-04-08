package auth

import (
	authmodel "certification_server/src/models/auth"
	"context"
)

// IDownstreamGrantService 定义下游服务访问授权签发接口。
type IDownstreamGrantService interface {
	// IssueDownstreamGrant 根据认证上下文和目标服务签发下游访问授权。
	IssueDownstreamGrant(ctx context.Context, req *authmodel.DownstreamGrantRequest) (*authmodel.DownstreamAccessGrant, error)
}
