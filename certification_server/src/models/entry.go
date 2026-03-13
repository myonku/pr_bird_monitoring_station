package models

import "github.com/google/uuid"

type UserRole string
type DeviceStatus string

const (
	UserRoleAdmin UserRole = "admin"
	UserRoleUser  UserRole = "user"
)

const (
	DeviceStatusActive   DeviceStatus = "active"
	DeviceStatusDisabled DeviceStatus = "disabled"
	DeviceStatusBlocked  DeviceStatus = "blocked"
	DeviceStatusInvoked  DeviceStatus = "invoked"
)

// User 代表认证服务器中的用户实体。
type User struct {
	ID           uuid.UUID
	AccountID    string
	UserName     string
	PasswordHash string
	Role         UserRole
}

// EdgeDevice 代表认证服务器中的边缘设备实体。
type EdgeDevice struct {
	ID               uuid.UUID
	Name             string
	DeviceSecretHash string
	Zone             string
	Status           DeviceStatus
	LastOnline       int64
}

// ServiceEntry 代表认证服务器中的服务实体。
type ServiceEntry struct {
	ID                   uuid.UUID
	Name                 string
	ServiceSecretHash    string
	ActiveCommKeyID      string
	KeyOwnerType         CommKeyOwnerType
	RequireAppEncryption bool
}

// ServiceInstance 定义服务实例的基本信息，用于服务发现和注册。
type ServiceInstance struct {
	ID                   uuid.UUID         `json:"id"`                     // 服务实例ID
	ServiceID            string            `json:"service_id"`             // 服务实体ID，用于关联全局公钥目录
	Name                 string            `json:"name"`                   // 服务名称
	Endpoint             string            `json:"endpoint"`               // 服务访问地址，如 "host:port"
	HeartBeat            int64             `json:"heartbeat"`              // 上次心跳时间戳，单位毫秒
	Zone                 string            `json:"zone"`                   // 服务所在的可用区或数据中心
	Version              string            `json:"version"`                // 服务版本信息
	Weight               int               `json:"weight"`                 // 负载均衡权重
	Tags                 []string          `json:"tags"`                   // 服务标签列表
	ActiveCommKeyID      string            `json:"active_comm_key_id"`     // 当前服务实例对外公布的通信公钥ID
	RequireAppEncryption bool              `json:"require_app_encryption"` // 是否要求内部 gRPC 调用具备应用层加密
	MetaData             map[string]string `json:"metadata"`               // 其他元信息
}

// ServiceSnapshot 定义服务快照信息，用于服务发现和注册。
type ServiceSnapshot struct {
	Name      string             `json:"name"`      // 服务名称
	Instances []*ServiceInstance `json:"instances"` // 服务实例列表
	Revision  int64              `json:"revision"`  // 快照版本号
}
