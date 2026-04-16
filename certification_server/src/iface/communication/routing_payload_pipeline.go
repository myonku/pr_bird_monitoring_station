package communication

import "context"

// FlowCategory 定义 certification_server 的入站流量类别。
type FlowCategory string

const (
	FlowCategoryBootstrapCall      FlowCategory = "bootstrap_call"
	FlowCategoryRemoteAuthVerify   FlowCategory = "remote_auth_verify"
	FlowCategoryExternalAuth       FlowCategory = "external_auth_forward"
	FlowCategoryModuleTokenRefresh FlowCategory = "module_token_refresh"
)

// SecurityPolicy 定义安全通道要求级别。
type SecurityPolicy string

const (
	SecurityPolicyRequired SecurityPolicy = "required"
	SecurityPolicyOptional SecurityPolicy = "optional"
	SecurityPolicyDisabled SecurityPolicy = "disabled"
)

// InboundPolicyPlan 是构建后的入站策略结果。
type InboundPolicyPlan struct {
	RouteProfile *RouteProfile

	RequiredScopes []string
	Tags           map[string]string
}

// IRoutingPayloadPipeline 定义 certification_server 的路由分类与策略构建。
//
// 下游接口调用：
//   - common.IKeyManager.LookupPublicKey
type IRoutingPayloadPipeline interface {
	ResolveRouteProfile(ctx context.Context, input *RoutingInput) (*RouteProfile, error)
	ClassifyFlow(ctx context.Context, input *RoutingInput) (FlowCategory, error)
	BuildInboundPolicy(ctx context.Context, input *RoutingInput) (*InboundPolicyPlan, error)
}
