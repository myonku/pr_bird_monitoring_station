package auth

import (
	"context"
	authmodel "gateway/src/models/auth"
)

// IModuleCredentialManager 负责网关本模块凭证的本地生命周期管理。
// 语义边界：持有与刷新本模块凭证；不承担认证中心权威签发职责。
type IModuleCredentialManager interface {
	EnsureActive(ctx context.Context) (*authmodel.BootstrapAuthResult, error)
	Snapshot() *authmodel.BootstrapAuthResult
	Revoke(ctx context.Context, reason string, revokedBy string) error
}
