package common

import (
	"context"

	commonmodel "gateway/src/models/common"
)

// FlowCategory 定义通信下层识别出的流量类别。
type FlowCategory string

const (
	FlowCategoryBootstrapCall     FlowCategory = "bootstrap_call"
	FlowCategoryRemoteAuthVerify  FlowCategory = "remote_auth_verify"
	FlowCategoryExternalAuthRelay FlowCategory = "external_auth_forward"
	FlowCategoryBusinessForward   FlowCategory = "business_forward"
	FlowCategoryTargetReverify    FlowCategory = "target_reverify_call"
)

// SecurityPolicy 定义通信下层对安全通道的要求。
type SecurityPolicy string

const (
	SecurityPolicyRequired SecurityPolicy = "required"
	SecurityPolicyOptional SecurityPolicy = "optional"
	SecurityPolicyDisabled SecurityPolicy = "disabled"
)

// TargetServiceType 定义路由解析得到的目标服务类型。
type TargetServiceType string

const (
	TargetServiceTypeAuthAuthority TargetServiceType = "auth_authority"
	TargetServiceTypeInternal      TargetServiceType = "internal_service"
	TargetServiceTypeUnknown       TargetServiceType = "unknown"
)

// FlowRouteInput 是通信下层进行路由与分流判断的统一输入。
type FlowRouteInput struct {
	RouteKey string

	Transport string
	Method    string
	Path      string

	SourceService     string
	TargetServiceHint string

	Metadata map[string]string
}

// RouteProfile 是通信下层产出的最小路由与安全策略快照。
type RouteProfile struct {
	TargetServiceType TargetServiceType
	TargetServiceName string
	TargetEndpoint    string

	FlowCategory   FlowCategory
	SecurityPolicy SecurityPolicy
}

// IServiceResolver 定义网关内部服务解析能力。
type IServiceResolver interface {
	// ResolveServiceType 解析当前流量对应的目标服务类型。
	ResolveServiceType(ctx context.Context, flow *FlowRouteInput) (TargetServiceType, error)
	// ResolveTargetInstance 解析并选择目标服务实例。
	ResolveTargetInstance(ctx context.Context, flow *FlowRouteInput) (*commonmodel.ServiceInstance, error)
	// ResolveRouteProfile 一次性解析完整路由与安全策略快照。
	ResolveRouteProfile(ctx context.Context, flow *FlowRouteInput) (*RouteProfile, error)
}
