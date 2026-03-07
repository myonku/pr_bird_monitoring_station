package models

import "github.com/google/uuid"

// User 代表认证服务器中的用户实体。
type User struct {
	ID           uuid.UUID
	Name         string
	PasswordHash string
}

// EdgeDevice 代表认证服务器中的边缘设备实体。
type EdgeDevice struct {
	ID           uuid.UUID
	Name         string
	DeviceSecret string
}
