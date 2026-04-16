package common

import "github.com/google/uuid"

type UserStatus string
type UserRole string
type DeviceStatus string

const (
	UserRoleAdmin UserRole = "admin"
	UserRoleUser  UserRole = "user"
)

const (
	DeviceStatusOnline  DeviceStatus = "online"
	DeviceStatusOffline DeviceStatus = "offline"
	DeviceStatusError   DeviceStatus = "error"
	DeviceStatusUnknown DeviceStatus = "unknown"
)

const (
	UserStatusActive   UserStatus = "active"
	UserStatusInactive UserStatus = "inactive"
	UserStatusBanned   UserStatus = "banned"
)

// 用户实体定义，包含用户的基本信息和认证相关字段。
type User struct {
	ID                uuid.UUID         `json:"id"`                  // 用户ID，唯一标识一个用户
	UserProfileID     uuid.UUID         `json:"user_profile_id"`     // 关联业务侧 profile 的唯一标识（profile 本体由外部模块维护）
	Name              string            `json:"name"`                // 用户名称
	Role              UserRole          `json:"role"`                // 用户角色，如管理员或普通用户
	PasswordHash      string            `json:"password_hash"`       // 用户密码的哈希值，用于认证验证
	HashAlgorithm     string            `json:"hash_algorithm"`      // 密码哈希算法，如 bcrypt、argon2 等
	Email             string            `json:"email"`               // 用户邮箱地址
	Phone             string            `json:"phone"`               // 用户手机号
	Status            UserStatus        `json:"status"`              // 用户状态，如活跃、非活跃或被封禁
	CreatedAt         int64             `json:"created_at"`          // 用户创建时间，单位毫秒
	UpdatedAt         int64             `json:"updated_at"`          // 用户更新时间，单位毫秒
	LastLoginAt       int64             `json:"last_login_at"`       // 用户最后登录时间，单位毫秒
	PasswordUpdatedAt int64             `json:"password_updated_at"` // 用户密码最后更新时间，单位毫秒
	MetaData          map[string]string `json:"metadata"`            // 其他元信息，如邮箱、手机号等
}

// 设备实体定义，包含设备的基本信息和认证相关字段。
type DeviceEntity struct {
	ID              uuid.UUID         `json:"id"`                 // 站点ID，唯一标识一个站点
	Name            string            `json:"name"`               // 站点名称
	LocationName    string            `json:"location_name"`      // 设备所在位置的名称
	Latitude        float64           `json:"latitude"`           // 设备所在位置的纬度
	Longitude       float64           `json:"longitude"`          // 设备所在位置的经度
	LastHeartbeatAt int64             `json:"last_heartbeat_at"`  // 设备最后一次心跳时间，单位毫秒
	Status          DeviceStatus      `json:"status"`             // 设备状态，如在线、离线等
	ActiveCommKeyID uuid.UUID         `json:"active_comm_key_id"` // 当前设备实例对外公布的通信公钥ID
	CreatedAt       int64             `json:"created_at"`         // 设备创建时间，单位毫秒
	UpdatedAt       int64             `json:"updated_at"`         // 设备更新时间，单位毫秒
	MetaData        map[string]string `json:"metadata"`           // 其他元信息，如设备型号、固件版本等
}

// 服务实体定义，包含服务的基本信息和认证相关字段。
// 暂时作为预留，后续可以根据实际业务需求进行调整和扩展。
type ServiceEntity struct {
	ID              uuid.UUID         `json:"id"`                 // 服务ID，唯一标识一个服务
	Name            string            `json:"name"`               // 服务名称
	Type            string            `json:"type"`               // 服务类型，如数据处理、认证服务等
	Endpoint        string            `json:"endpoint"`           // 服务访问地址，如 "host:port"
	ActiveCommKeyID uuid.UUID         `json:"active_comm_key_id"` // 当前服务实例对外公布的通信公钥ID
	LastHeartbeatAt int64             `json:"last_heartbeat_at"`  // 服务最后一次心跳时间，单位毫秒
	UpdatedAt       int64             `json:"updated_at"`         // 服务更新时间，单位毫秒
	CreatedAt       int64             `json:"created_at"`         // 服务创建时间，单位毫秒
	MetaData        map[string]string `json:"metadata"`           // 其他元信息，如服务版本、维护联系人等
}
