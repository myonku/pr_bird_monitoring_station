package communication

// RoutingInput 是 communication 包共享的路由输入契约。
type RoutingInput struct {
	RouteKey string

	Transport string
	Method    string
	Path      string

	SourceService     string
	TargetService     string
	TargetServiceHint string

	Metadata map[string]string
}

// RouteProfile 是 communication 包共享的路由画像契约。
type RouteProfile struct {
	TargetServiceType string
	TargetServiceName string
	TargetEndpoint    string

	FlowCategory   FlowCategory
	SecurityPolicy SecurityPolicy

	Operation string
	Metadata  map[string]string
}
