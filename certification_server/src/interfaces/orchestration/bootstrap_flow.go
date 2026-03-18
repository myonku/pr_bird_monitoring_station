package orchestration

import (
	authmodel "certification_server/src/models/auth"
	commsecmodel "certification_server/src/models/commsec"
	"context"
)

// BootstrapStartFlowRequest 表示 bootstrap 起始阶段（申请 challenge）的编排输入。
type BootstrapStartFlowRequest struct {
	ChallengeRequest *authmodel.ChallengeRequest
}

// BootstrapFinishFlowRequest 表示 bootstrap 完成阶段（验签并签发凭证）的编排输入。
type BootstrapFinishFlowRequest struct {
	AuthRequest *authmodel.BootstrapAuthRequest

	// 当需要在 bootstrap 后立即下发下游授权时，设置目标服务与绑定参数。
	IssueDownstreamGrant bool
	TargetService        string
	BindingType          commsecmodel.ChannelBindingType
	GrantTTLSec          int64
}

// BootstrapFlowResult 表示 bootstrap 编排结果。
type BootstrapFlowResult struct {
	Challenge *authmodel.ChallengePayload
	Auth      *authmodel.BootstrapAuthResult
	Grant     *authmodel.DownstreamAccessGrant
}

// IBootstrapOrchestrator 定义认证中心 bootstrap 统合编排接口。
// 引用: certification_server/src/interfaces/auth/bootstrap.go,
// certification_server/src/interfaces/auth/session_svc.go,
// certification_server/src/interfaces/auth/token_svc.go,
// certification_server/src/interfaces/auth/downstream_grant_svc.go。
type IBootstrapOrchestrator interface {
	// StartFlow 执行 bootstrap 起始编排：阶段检查 + challenge 签发。
	StartFlow(ctx context.Context, req *BootstrapStartFlowRequest) (*BootstrapFlowResult, error)
	// FinishFlow 执行 bootstrap 完成编排：challenge 验签 + session/token + 可选 downstream grant。
	FinishFlow(ctx context.Context, req *BootstrapFinishFlowRequest) (*BootstrapFlowResult, error)
	// GetStage 返回指定实体当前 bootstrap 阶段。
	GetStage(ctx context.Context, entityType authmodel.EntityType, entityID string) (authmodel.BootstrapStage, error)
}
