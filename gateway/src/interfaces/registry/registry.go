package registry

import (
	registrymodel "gateway/src/models/registry"
)

// 服务注册接口定义
type IRegistry interface {
	// Register 注册服务实例，ttl 单位为秒。
	Register(instance *registrymodel.ServiceInstance, ttl int64) error
	// UnRegister 注销服务实例。
	UnRegister(instance *registrymodel.ServiceInstance) error
	// GetServiceInstances 获取服务实例列表。
	GetServiceInstances(serviceName string) ([]*registrymodel.ServiceInstance, error)
	// GetServiceSnapShot 获取指定的本地服务快照。
	GetServiceSnapShot(serviceName string) (*registrymodel.ServiceSnapshot, error)
}

// 服务发现适配器接口定义
type IDiscoveryAdapter interface {
	// ChooseEndpoint 选择服务实例，affinityKey 用于实现会话亲和，requireTags 用于过滤实例。
	ChooseEndpoint(serviceName string, affinityKey string, requireTags []string) (*registrymodel.ServiceInstance, error)
}
