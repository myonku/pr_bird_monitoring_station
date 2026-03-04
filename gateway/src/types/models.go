package src

type SessionType string

const (
	UserSession   SessionType = "user" // 用户会话
	DeviceSession SessionType = "dev"  // 设备会话
)

// 通用的会话模型，包括用户会话或设备会话
type Session struct {
	ID   string      `json:"id"`   // 会话ID
	Type SessionType `json:"type"` // 会话对象类型
}
