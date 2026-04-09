package authcontrol

import (
	"context"

	commonif "gateway/src/iface/common"
	authmodel "gateway/src/models/auth"
)

// BootstrapEnsureReadyRequest 定义了网关模块引导认证准备就绪的输入参数，
// 包括引导认证挑战请求、模块角色和权限范围，以及是否需要下游访问令牌等信息。
type BootstrapEnsureReadyRequest struct {
	ChallengeRequest *authmodel.ChallengeRequest

	Role   string
	Scopes []string

	RequireDownstreamToken bool
}

// IBootstrapCoordinator 负责对网关的 bootstrap 生命周期进行编排。
//
// 下游接口调用:
//   - common.IKeyManager.GetPrivateKeyRef / GetPublicKey
//   - authcontrol.IAuthAuthorityClient.InitBootstrapChallenge / AuthenticateBootstrap / RefreshTokenBundle / RevokeToken
//   - common.ILocalCredentialManager.SaveBootstrapCredential / LoadActiveCredential / MarkCredentialExpired / RevokeCredential
type IBootstrapCoordinator interface {
	EnsureModuleReady(ctx context.Context, req *BootstrapEnsureReadyRequest) (*commonif.ModuleCredentialSnapshot, error)
	RefreshModuleCredential(ctx context.Context, req *TokenRefreshRequest) (*commonif.ModuleCredentialSnapshot, error)
	RevokeModuleCredential(ctx context.Context, req *TokenRevokeRequest) error
}
