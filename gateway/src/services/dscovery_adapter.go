package services

import (
	"sync/atomic"

	"gateway/src"
	"gateway/src/models"
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

// ChooseEndpoint 选择服务实例。
func (d *DiscoveryAdapter) ChooseEndpoint(
	serviceName string, affinityKey string, requireTags []string) (models.ServiceInstance, error) {

	if d.registry == nil {
		return models.ServiceInstance{}, &models.ErrNilRegistryClient
	}
	if serviceName == "" {
		return models.ServiceInstance{}, &models.ErrServiceNameRequired
	}

	instances, err := d.registry.GetServiceInstances(serviceName)
	if err != nil {
		return models.ServiceInstance{}, err
	}
	if len(instances) == 0 {
		return models.ServiceInstance{}, &models.ErrNoAvaliableInstances
	}

	ptrs := make([]*models.ServiceInstance, 0, len(instances))
	for i := range instances {
		instCopy := instances[i]
		ptrs = append(ptrs, &instCopy)
	}

	filtered := utils.FilterByTags(ptrs, requireTags)
	if len(filtered) == 0 {
		return models.ServiceInstance{}, &models.ErrNoMatchingTags
	}

	var selected *models.ServiceInstance
	if affinityKey != "" {
		selected = utils.PickHashAffinity(filtered, affinityKey)
	} else {
		idx := int(d.counter.Add(1) - 1)
		selected = utils.PickRoundRobin(filtered, idx)
	}

	if selected == nil || selected.Endpoint == "" {
		return models.ServiceInstance{}, &models.ErrInvalidInstance
	}
	return *selected, nil
}
