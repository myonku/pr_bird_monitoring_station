package services

import (
	"sync/atomic"

	registryif "gateway/src/interfaces/registry"
	registrymodel "gateway/src/models/registry"
	modelsystem "gateway/src/models/system"
	"gateway/src/utils"
)

var _ registryif.IDiscoveryAdapter = (*DiscoveryAdapter)(nil)

// DiscoveryAdapter 将服务快照转换为具体 endpoint 选择。
type DiscoveryAdapter struct {
	registry registryif.IRegistry
	counter  atomic.Uint64
}

// NewDiscoveryAdapter 创建服务发现适配器。
func NewDiscoveryAdapter(registry registryif.IRegistry) registryif.IDiscoveryAdapter {
	return &DiscoveryAdapter{registry: registry}
}

// ChooseEndpoint 选择服务实例。
func (d *DiscoveryAdapter) ChooseEndpoint(
	serviceName string, affinityKey string, requireTags []string) (registrymodel.ServiceInstance, error) {

	if d.registry == nil {
		return registrymodel.ServiceInstance{}, &modelsystem.ErrNilRegistryClient
	}
	if serviceName == "" {
		return registrymodel.ServiceInstance{}, &modelsystem.ErrServiceNameRequired
	}

	instances, err := d.registry.GetServiceInstances(serviceName)
	if err != nil {
		return registrymodel.ServiceInstance{}, err
	}
	if len(instances) == 0 {
		return registrymodel.ServiceInstance{}, &modelsystem.ErrNoAvaliableInstances
	}

	ptrs := make([]*registrymodel.ServiceInstance, 0, len(instances))
	for i := range instances {
		instCopy := instances[i]
		ptrs = append(ptrs, &instCopy)
	}

	filtered := utils.FilterByTags(ptrs, requireTags)
	if len(filtered) == 0 {
		return registrymodel.ServiceInstance{}, &modelsystem.ErrNoMatchingTags
	}

	var selected *registrymodel.ServiceInstance
	if affinityKey != "" {
		selected = utils.PickHashAffinity(filtered, affinityKey)
	} else {
		idx := int(d.counter.Add(1) - 1)
		selected = utils.PickRoundRobin(filtered, idx)
	}

	if selected == nil || selected.Endpoint == "" {
		return registrymodel.ServiceInstance{}, &modelsystem.ErrInvalidInstance
	}
	return *selected, nil
}
