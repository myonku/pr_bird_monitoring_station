package communication

import (
	"context"
	"sort"
	"strings"

	commif "gateway/src/interfaces/communication"
	registryif "gateway/src/interfaces/registry"
	modelsystem "gateway/src/models/system"
)

var _ commif.IOutboundTargetResolver = (*TargetResolverService)(nil)

// RouteRule 定义路由到服务发现选择的一条规则。
type RouteRule struct {
	RouteKey     string
	Method       string
	PathPrefix   string
	ServiceName  string
	TimeoutMS    int64
	RequiredTags []string
	AffinityFrom string
}

// TargetResolverService 负责将入站规范化请求映射为内部目标服务。
type TargetResolverService struct {
	Discovery registryif.IDiscoveryAdapter
	Rules     []RouteRule
}

func NewTargetResolverService(discovery registryif.IDiscoveryAdapter, rules []RouteRule) *TargetResolverService {
	copied := append([]RouteRule(nil), rules...)
	sort.SliceStable(copied, func(i, j int) bool {
		return len(copied[i].PathPrefix) > len(copied[j].PathPrefix)
	})
	return &TargetResolverService{Discovery: discovery, Rules: copied}
}

func (s *TargetResolverService) Resolve(
	ctx context.Context,
	req *commif.ResolveTargetRequest,
) (*commif.ResolveTargetResult, error) {
	if s == nil || s.Discovery == nil {
		return nil, &modelsystem.ErrResolverDependenciesRequired
	}
	if req == nil {
		return nil, &modelsystem.ErrResolveTargetRequestNil
	}

	rule := s.selectRule(req)
	if rule == nil {
		return nil, &modelsystem.ErrRouteRuleNotFound
	}
	requiredTags := append([]string(nil), rule.RequiredTags...)
	requiredTags = append(requiredTags, req.RequiredTags...)

	affinityKey := req.AffinityKey
	if affinityKey == "" && rule.AffinityFrom != "" {
		affinityKey = req.Headers[rule.AffinityFrom]
	}

	instance, err := s.Discovery.ChooseEndpoint(rule.ServiceName, affinityKey, requiredTags)
	if err != nil {
		return nil, err
	}
	timeout := rule.TimeoutMS
	if timeout <= 0 {
		timeout = 3000
	}

	return &commif.ResolveTargetResult{
		ServiceName: rule.ServiceName,
		Endpoint:    instance.Endpoint,
		TimeoutMS:   timeout,
		PolicyTags:  append([]string(nil), requiredTags...),
	}, nil
}

func (s *TargetResolverService) selectRule(req *commif.ResolveTargetRequest) *RouteRule {
	for i := range s.Rules {
		rule := &s.Rules[i]
		if rule.RouteKey != "" && req.RouteKey != "" && rule.RouteKey == req.RouteKey {
			return rule
		}
		if rule.Method != "" && !strings.EqualFold(rule.Method, req.Method) {
			continue
		}
		if rule.PathPrefix != "" {
			if strings.HasPrefix(req.Path, rule.PathPrefix) {
				return rule
			}
			for _, fallbackPath := range req.FallbackPaths {
				if strings.HasPrefix(fallbackPath, rule.PathPrefix) {
					return rule
				}
			}
		}
	}
	return nil
}
