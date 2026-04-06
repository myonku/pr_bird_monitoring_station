package common

import "github.com/google/uuid"

type EntityType string // 认证实体类型，表示认证对象的类别，可以是用户、设备或服务等。
type UserRole string
type DeviceStatus string

const (
	UserRoleAdmin UserRole = "admin"
	UserRoleUser  UserRole = "user"
)

const (
	EntityUser    EntityType = "user"
	EntityDevice  EntityType = "device"
	EntityService EntityType = "service"
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
	ID                uuid.UUID
	Name              string
	ServiceSecretHash string
	ActiveCommKeyID   string
	KeyEntityType     string
}
