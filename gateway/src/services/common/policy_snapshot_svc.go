package common

import (
	"context"
	"strings"
	"sync"
	"time"

	commonif "gateway/src/iface/common"
)

const defaultGatewayPolicySet = "gateway-default"

var _ commonif.IPolicySnapshotManager = (*PolicySnapshotService)(nil)

// PolicySnapshotService 提供网关运行期策略快照的最小实现。
type PolicySnapshotService struct {
	mu sync.RWMutex

	policySet string
	runMode   string
	version   string

	snapshot *commonif.PolicySnapshot
}

func NewPolicySnapshotService(policySet string, runMode string) commonif.IPolicySnapshotManager {
	resolvedPolicySet := strings.TrimSpace(policySet)
	if resolvedPolicySet == "" {
		resolvedPolicySet = defaultGatewayPolicySet
	}

	resolvedRunMode := strings.TrimSpace(strings.ToLower(runMode))
	if resolvedRunMode == "" {
		resolvedRunMode = "development"
	}

	return &PolicySnapshotService{
		policySet: resolvedPolicySet,
		runMode:   resolvedRunMode,
		version:   "route-mapping-v1",
	}
}

func (s *PolicySnapshotService) LoadPolicySnapshot(
	ctx context.Context,
	policySet string,
) (*commonif.PolicySnapshot, error) {
	_ = ctx

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.snapshot == nil {
		s.snapshot = s.buildSnapshotLocked()
	}
	return clonePolicySnapshot(s.snapshot), nil
}

func (s *PolicySnapshotService) RefreshPolicySnapshot(
	ctx context.Context,
	policySet string,
) (*commonif.PolicySnapshot, error) {
	_ = ctx
	_ = policySet

	s.mu.Lock()
	defer s.mu.Unlock()

	fresh := s.buildSnapshotLocked()
	fresh.RefreshedAt = time.Now()
	s.snapshot = fresh
	return clonePolicySnapshot(fresh), nil
}

func (s *PolicySnapshotService) GetRouteMappingVersion(ctx context.Context) (string, error) {
	_ = ctx

	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.version, nil
}

func (s *PolicySnapshotService) buildSnapshotLocked() *commonif.PolicySnapshot {
	now := time.Now()

	return &commonif.PolicySnapshot{
		PolicySet:           s.policySet,
		RuntimeMode:         s.runMode,
		RouteMappingVersion: s.version,
		RouteMappings:       buildDefaultGatewayRouteMappings(s.runMode),
		FeatureFlags: map[string]bool{
			"traffic_station_enabled":  true,
			"routing_pipeline_enabled": true,
		},
		Metadata: map[string]string{
			"owner": "gateway",
		},
		LoadedAt:    now,
		RefreshedAt: now,
	}
}

func buildDefaultGatewayRouteMappings(runMode string) map[string]commonif.RouteProfile {
	securityRequired := commonif.SecurityPolicyRequired
	securityOptional := commonif.SecurityPolicyOptional
	if strings.EqualFold(strings.TrimSpace(runMode), "no_auth") {
		securityRequired = commonif.SecurityPolicyDisabled
		securityOptional = commonif.SecurityPolicyDisabled
	}

	return map[string]commonif.RouteProfile{
		string(commonif.FlowCategoryBootstrapCall): {
			TargetServiceType: commonif.TargetServiceTypeAuthAuthority,
			TargetServiceName: "certification_server",
			FlowCategory:      commonif.FlowCategoryBootstrapCall,
			SecurityPolicy:    securityOptional,
		},
		string(commonif.FlowCategoryRemoteAuthVerify): {
			TargetServiceType: commonif.TargetServiceTypeAuthAuthority,
			TargetServiceName: "certification_server",
			FlowCategory:      commonif.FlowCategoryRemoteAuthVerify,
			SecurityPolicy:    securityRequired,
		},
		string(commonif.FlowCategoryExternalAuthRelay): {
			TargetServiceType: commonif.TargetServiceTypeAuthAuthority,
			TargetServiceName: "certification_server",
			FlowCategory:      commonif.FlowCategoryExternalAuthRelay,
			SecurityPolicy:    securityRequired,
		},
		string(commonif.FlowCategoryBusinessForward): {
			TargetServiceType: commonif.TargetServiceTypeInternal,
			FlowCategory:      commonif.FlowCategoryBusinessForward,
			SecurityPolicy:    securityRequired,
		},
		string(commonif.FlowCategoryTargetReverify): {
			TargetServiceType: commonif.TargetServiceTypeAuthAuthority,
			TargetServiceName: "certification_server",
			FlowCategory:      commonif.FlowCategoryTargetReverify,
			SecurityPolicy:    securityRequired,
		},
	}
}

func clonePolicySnapshot(src *commonif.PolicySnapshot) *commonif.PolicySnapshot {
	if src == nil {
		return nil
	}

	cloned := *src
	cloned.RouteMappings = make(map[string]commonif.RouteProfile, len(src.RouteMappings))
	for key, value := range src.RouteMappings {
		cloned.RouteMappings[key] = value
	}
	cloned.FeatureFlags = make(map[string]bool, len(src.FeatureFlags))
	for key, value := range src.FeatureFlags {
		cloned.FeatureFlags[key] = value
	}
	cloned.Metadata = make(map[string]string, len(src.Metadata))
	for key, value := range src.Metadata {
		cloned.Metadata[key] = value
	}
	return &cloned
}
