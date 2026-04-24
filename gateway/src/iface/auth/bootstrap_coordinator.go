package auth

import (
	"context"

	commonif "gateway/src/iface/common"
)

// IBootstrapCoordinator 负责对网关模块凭证生命周期进行编排。
//
// 它聚合了启动期 bootstrap、运行期 refresh 和失效处理的编排能力，
// 让上层只依赖一个模块级协调面，而不直接绑定 bootstrap/refresh 的底层 RPC 细节。
type IBootstrapCoordinator interface {
	EnsureModuleReady(ctx context.Context) (*commonif.ModuleCredentialSnapshot, error)
	RefreshModuleCredential(ctx context.Context) (*commonif.ModuleCredentialSnapshot, error)
	RevokeModuleCredential(ctx context.Context, reason string) error
}
