package services

import (
	"errors"
	"sync/atomic"

	"gateway/src"
	"gateway/src/types"
	"gateway/src/utils"
)

var _ src.IDiscoveryAdapter = (*DiscoveryAdapter)(nil)

// DiscoveryAdapter 将服务快照转换为具体 endpoint 选择。
type DiscoveryAdapter struct {
	registry src.IRegistry
	counter  atomic.Uint64
}

// NewDiscoveryAdapter 创建服务发现适配器。
func NewDiscoveryAdapter(registry src.IRegistry) src.IDiscoveryAdapter {
	return &DiscoveryAdapter{registry: registry}
}

// ChooseEndpoint 选择服务实例 endpoint。
func (d *DiscoveryAdapter) ChooseEndpoint(
	serviceName string, affinityKey string, requireTags []string) (string, error) {

	if d.registry == nil {
		return "", errors.New("registry is nil")
	}
	if serviceName == "" {
		return "", errors.New("serviceName is required")
	}

	instances, err := d.registry.GetServiceInstances(serviceName)
	if err != nil {
		return "", err
	}
	if len(instances) == 0 {
		return "", errors.New("no service instances available")
	}

	ptrs := make([]*types.ServiceInstance, 0, len(instances))
	for i := range instances {
		instCopy := instances[i]
		ptrs = append(ptrs, &instCopy)
	}

	filtered := utils.FilterByTags(ptrs, requireTags)
	if len(filtered) == 0 {
		return "", errors.New("no service instances match required tags")
	}

	var selected *types.ServiceInstance
	if affinityKey != "" {
		selected = utils.PickHashAffinity(filtered, affinityKey)
	} else {
		idx := int(d.counter.Add(1) - 1)
		selected = utils.PickRoundRobin(filtered, idx)
	}

	if selected == nil || selected.Endpoint == "" {
		return "", errors.New("selected service instance is invalid")
	}
	return selected.Endpoint, nil
}
