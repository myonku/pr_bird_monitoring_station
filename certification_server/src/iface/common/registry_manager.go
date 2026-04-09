package common

import commonmodel "certification_server/src/models/common"

// IRegistryManager 定义公共服务发现和注册相关操作。
type IRegistryManager interface {
	// Register 注册服务实例，ttl参数指定实例的生存时间，单位为秒。
	Register(instance *commonmodel.ServiceInstance, ttl int64) error
	// UnRegister 注销服务实例。
	UnRegister(instance *commonmodel.ServiceInstance) error
	// GetServiceInstances 获取指定服务名称的所有可用实例列表。
	GetServiceInstances(serviceName string) ([]*commonmodel.ServiceInstance, error)
	// GetServiceSnapShot 获取指定服务名称的当前服务快照信息，包含实例列表和版本等元数据。
	GetServiceSnapShot(serviceName string) (*commonmodel.ServiceSnapshot, error)
	// ChooseEndpoint 根据服务名称、亲和性键和要求的标签选择一个合适的服务实例，支持负载均衡和标签过滤等功能。
	ChooseEndpoint(serviceName string, affinityKey string, requireTags []string) (*commonmodel.ServiceInstance, error)
}
