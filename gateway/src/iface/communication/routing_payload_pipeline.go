package communication

import (
	"context"

	commonif "gateway/src/iface/common"
	commonmodel "gateway/src/models/common"
	commsecmodel "gateway/src/models/commsec"
)

// BuildOutboundPayloadRequest 是路由/载荷流水线输入。
type BuildOutboundPayloadRequest struct {
	Flow            *commonif.FlowRouteInput
	PlainPayload    string
	AdditionalData  map[string]string
	EnsureChannel   *SecureChannelEnsureRequest
	PreferredTarget *commonmodel.ServiceInstance
}

// OutboundPayloadPlan 是路由/载荷流水线输出。
type OutboundPayloadPlan struct {
	RouteProfile *commonif.RouteProfile
	Target       *commonmodel.ServiceInstance

	PlainPayload string
	Encrypted    *EncryptedPayload
	Channel      *commsecmodel.SecureChannelSession
}

// IRoutingPayloadPipeline 定义路由分类与载荷构建操作。
//
// 下游接口调用：
//   - common.IServiceResolver.ResolveRouteProfile / ResolveTargetInstance
//   - common.IPolicySnapshotManager.LoadPolicySnapshot
//   - communication.ICommsecChannelManager.EnsureChannel / EncryptPayload
type IRoutingPayloadPipeline interface {
	ResolveRouteProfile(ctx context.Context, flow *commonif.FlowRouteInput) (*commonif.RouteProfile, error)
	ClassifyFlow(ctx context.Context, flow *commonif.FlowRouteInput) (commonif.FlowCategory, error)
	BuildOutboundPayload(ctx context.Context, req *BuildOutboundPayloadRequest) (*OutboundPayloadPlan, error)
}
