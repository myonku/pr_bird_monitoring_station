package common

type EntityType string // 认证实体类型，表示认证对象的类别，可以是用户、设备或服务等。

// EntityType 只作为后端服务中的实体分类定义，不适应于存储层的表设计，
// 存储层的表设计应该根据实际业务需求进行调整。

const (
	EntityUser    EntityType = "user"
	EntityDevice  EntityType = "device"
	EntityService EntityType = "service"
	EntryUnknown  EntityType = "unknown"
)
