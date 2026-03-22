package services

import (
	"sync/atomic"
	"time"

	registryif "certification_server/src/interfaces/registry"
	registrymodel "certification_server/src/models/registry"
	modelsystem "certification_server/src/models/system"
	"certification_server/src/utils"
)

var _ registryif.IDiscoveryAdapter = (*DiscoveryAdapter)(nil)

// DiscoveryAdapter 将服务快照转换为具体 endpoint 选择。
type DiscoveryAdapter struct {
	registry registryif.IRegistry
	counter  atomic.Uint64
	maxStale time.Duration
}

// NewDiscoveryAdapter 创建服务发现适配器。
func NewDiscoveryAdapter(registry registryif.IRegistry) registryif.IDiscoveryAdapter {
	return &DiscoveryAdapter{registry: registry, maxStale: 30 * time.Second}
}

// NewDiscoveryAdapterWithStaleWindow 支持配置心跳可接受窗口。
func NewDiscoveryAdapterWithStaleWindow(
	registry registryif.IRegistry,
	maxStale time.Duration,
) registryif.IDiscoveryAdapter {
	if maxStale <= 0 {
		maxStale = 30 * time.Second
	}
	return &DiscoveryAdapter{registry: registry, maxStale: maxStale}
}

// ChooseEndpoint 选择服务实例。
func (d *DiscoveryAdapter) ChooseEndpoint(
	serviceName string, affinityKey string, requireTags []string) (*registrymodel.ServiceInstance, error) {

	if d.registry == nil {
		return nil, &modelsystem.ErrNilRegistryClient
	}
	if serviceName == "" {
		return nil, &modelsystem.ErrNoAvaliableInstances
	}

	instances, err := d.registry.GetServiceInstances(serviceName)
	if err != nil {
		return nil, err
	}
	if len(instances) == 0 {
		return nil, &modelsystem.ErrNoAvaliableInstances
	}

	nowMS := time.Now().UnixMilli()
	alive := make([]*registrymodel.ServiceInstance, 0, len(instances))
	for i := range instances {
		inst := instances[i]
		if inst == nil {
			continue
		}
		if inst.HeartBeat > 0 && d.maxStale > 0 {
			if nowMS-inst.HeartBeat > d.maxStale.Milliseconds() {
				continue
			}
		}
		alive = append(alive, inst)
	}
	if len(alive) == 0 {
		return nil, &modelsystem.ErrNoAvaliableInstances
	}

	filtered := utils.FilterByTags(alive, requireTags)
	if len(filtered) == 0 {
		return nil, &modelsystem.ErrNoMatchingTags
	}

	var selected *registrymodel.ServiceInstance
	if affinityKey != "" {
		selected = utils.PickHashAffinity(filtered, affinityKey)
	} else {
		selected = utils.RandomWeighted(filtered)
		if selected == nil {
			idx := int(d.counter.Add(1) - 1)
			selected = utils.PickRoundRobin(filtered, idx)
		}
	}

	if selected == nil || selected.Endpoint == "" {
		return nil, &modelsystem.ErrInvalidInstance
	}
	return selected, nil
}
