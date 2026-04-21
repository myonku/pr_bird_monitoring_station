package orchestration

import (
	"context"

	commonif "gateway/src/iface/common"
)

// ForwardingRequest 是网关转发流程的编排请求。
type ForwardingRequest struct {
	Flow *commonif.FlowRouteInput

	InboundHeaders map[string]string
	Payload        string

	AffinityKey  string
	RequireTags  []string
	RuntimeMode  string
	RequestTrace map[string]string
}

// ForwardingResult 是网关转发流程的编排输出。
type ForwardingResult struct {
	RouteProfile   *commonif.RouteProfile
	TargetEndpoint string

	OutboundHeaders map[string]string
	OutboundPayload string
}

// IForwardingOrchestrator 定义网关顶层转发编排。
//
// 下游接口调用：
//   - communication.ITrafficStation.HandleInbound / SendOutbound
//   - communication.IRoutingPayloadPipeline.ResolveRouteProfile / BuildOutboundPayload
//   - common.IServiceResolver.ResolveTargetInstance
type IForwardingOrchestrator interface {
	HandleBusinessForward(ctx context.Context, req *ForwardingRequest) (*ForwardingResult, error)
	HandleExternalAuthForward(ctx context.Context, req *ForwardingRequest) (*ForwardingResult, error)
}
