package communication

import (
	"context"

	commonif "gateway/src/iface/common"
)

// InboundTrafficRequest 是发送到流量站点的统一入站信封。
type InboundTrafficRequest struct {
	Flow    *commonif.FlowRouteInput
	Headers map[string]string
	Payload string
}

// OutboundTrafficRequest 是从流量站点发出的统一出站信封。
type OutboundTrafficRequest struct {
	Flow    *commonif.FlowRouteInput
	Headers map[string]string
	Payload string
}

// TrafficDecision 是站点的决策输出。
type TrafficDecision struct {
	Accepted bool
	Reason   string

	Profile  *commonif.RouteProfile
	Metadata map[string]string
}

// TrafficDispatchResult 是站点的出站派发输出。
type TrafficDispatchResult struct {
	Profile        *commonif.RouteProfile
	TargetEndpoint string
	Payload        string
	Metadata       map[string]string
}

// ITrafficStation 定义模块级统一流量站点契约。
//
// 下游接口调用：
//   - communication.IRoutingPayloadPipeline.ResolveRouteProfile / BuildOutboundPayload
//   - authcontrol.IGatewayAuthControl.Enforce
//   - orchestration.IForwardingOrchestrator.HandleBusinessForward / HandleExternalAuthForward
type ITrafficStation interface {
	HandleInbound(ctx context.Context, req *InboundTrafficRequest) (*TrafficDecision, error)
	SendOutbound(ctx context.Context, req *OutboundTrafficRequest) (*TrafficDispatchResult, error)
}
