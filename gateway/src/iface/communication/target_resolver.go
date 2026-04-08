package communication

import "context"

// ResolveTargetRequest 表示一次外部请求转发时的目标解析输入。
type ResolveTargetRequest struct {
	RouteKey      string
	Method        string
	Path          string
	Headers       map[string]string
	AffinityKey   string
	RequiredTags  []string
	FallbackPaths []string
}

// ResolveTargetResult 表示目标解析结果。
type ResolveTargetResult struct {
	ServiceName string
	Endpoint    string
	TimeoutMS   int64
	PolicyTags  []string
}

// IOutboundTargetResolver 负责把外部请求映射到内部目标服务。
// 边界约束: 仅负责解析，不负责认证、握手和转发执行。
type IOutboundTargetResolver interface {
	Resolve(ctx context.Context, req *ResolveTargetRequest) (*ResolveTargetResult, error)
}
