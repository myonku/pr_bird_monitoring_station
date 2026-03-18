package auth

import (
	"context"
	authmodel "gateway/src/models/auth"
)

// IBootstrapFlowCoordinator 定义网关侧主动 bootstrap 编排接口。
// 语义: stage 检查 -> challenge 申请 -> 本地签名 -> bootstrap 认证。
// 引用: gateway/src/interfaces/auth/bootstrap_cli.go 中原子调用接口。
type IBootstrapFlowCoordinator interface {
	EnsureReady(ctx context.Context, req *authmodel.BootstrapEnsureReadyRequest) (*authmodel.BootstrapAuthResult, error)
}
