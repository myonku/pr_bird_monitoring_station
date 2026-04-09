package common

import (
	"context"
	"time"
)

// PolicySnapshot 描述网关运行时可消费的策略快照。
type PolicySnapshot struct {
	PolicySet           string
	RuntimeMode         string
	RouteMappingVersion string

	RouteMappings map[string]RouteProfile
	FeatureFlags  map[string]bool
	Metadata      map[string]string

	LoadedAt    time.Time
	RefreshedAt time.Time
}

// IPolicySnapshotManager 定义策略快照管理能力。
type IPolicySnapshotManager interface {
	// LoadPolicySnapshot 读取指定策略集的当前快照。
	LoadPolicySnapshot(ctx context.Context, policySet string) (*PolicySnapshot, error)
	// RefreshPolicySnapshot 强制刷新策略快照。
	RefreshPolicySnapshot(ctx context.Context, policySet string) (*PolicySnapshot, error)
	// GetRouteMappingVersion 返回当前路由映射版本。
	GetRouteMappingVersion(ctx context.Context) (string, error)
}
