package communication

import "context"

// InboundTrafficRequest 是发送到 certification 流量站点的统一入站信封。
type InboundTrafficRequest struct {
	Route *RoutingInput

	Headers map[string]string
	Payload string
}

// OutboundTrafficRequest 是从 certification 流量站点发出的统一出站信封。
type OutboundTrafficRequest struct {
	Route *RoutingInput

	Headers map[string]string
	Payload string
}

// TrafficDecision 是站点的入站决策输出。
type TrafficDecision struct {
	Accepted bool
	Reason   string

	Profile  *RouteProfile
	Metadata map[string]string
}

// TrafficDispatchResult 是站点的出站派发输出。
type TrafficDispatchResult struct {
	Profile  *RouteProfile
	Payload  string
	Metadata map[string]string
}

// ITrafficStation 定义 certification_server 统一流量站点契约。
//
// 下游接口调用：
//   - communication.IRoutingPayloadPipeline.ResolveRouteProfile / BuildInboundPolicy
//   - authcontrol.IInboundAuthControl.EnforceInbound
type ITrafficStation interface {
	HandleInbound(ctx context.Context, req *InboundTrafficRequest) (*TrafficDecision, error)
	SendOutbound(ctx context.Context, req *OutboundTrafficRequest) (*TrafficDispatchResult, error)
}
