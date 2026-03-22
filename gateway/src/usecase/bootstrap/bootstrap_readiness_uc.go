package bootstrap

import (
	"context"

	authif "gateway/src/interfaces/auth"
	authmodel "gateway/src/models/auth"
	modelsystem "gateway/src/models/system"
)

// ReadinessRequest 表示网关启动时的 bootstrap 就绪请求。
type ReadinessRequest struct {
	ChallengeRequest *authmodel.ChallengeRequest
	Role             string
	Scopes           []string

	RequireDownstreamToken bool
	Signer                 authmodel.ChallengeSigner
}

// IReadinessUsecase 定义启动就绪编排接口。
type IReadinessUsecase interface {
	Execute(ctx context.Context, req *ReadinessRequest) (*authmodel.BootstrapAuthResult, error)
}

// ReadinessUsecase 负责执行 stage 检查、challenge、签名和 bootstrap 认证。
type ReadinessUsecase struct {
	Coordinator authif.IBootstrapFlowCoordinator
}

// Execute 执行 bootstrap 就绪编排。
func (u *ReadinessUsecase) Execute(ctx context.Context, req *ReadinessRequest) (*authmodel.BootstrapAuthResult, error) {
	if u == nil || u.Coordinator == nil {
		return nil, &modelsystem.ErrBootstrapCoordinatorRequired
	}
	if req == nil || req.ChallengeRequest == nil {
		return nil, &modelsystem.ErrReadinessRequestInvalid
	}

	return u.Coordinator.EnsureReady(ctx, &authmodel.BootstrapEnsureReadyRequest{
		ChallengeRequest:       req.ChallengeRequest,
		Role:                   req.Role,
		Scopes:                 req.Scopes,
		RequireDownstreamToken: req.RequireDownstreamToken,
		Signer:                 req.Signer,
	})
}
