package models

import (
	"github.com/google/uuid"
)

type SessionType string

const (
	UserSession   SessionType = "user" // 用户会话
	DeviceSession SessionType = "dev"  // 设备会话
)

// 网关通用的会话模型，包括用户会话或设备会话
type GatewaySession struct {
	ID          uuid.UUID   `json:"id"`          // 会话ID
	Type        SessionType `json:"type"`        // 会话对象类型
	Fingerprint string      `json:"fingerprint"` // 会话指纹，用于唯一标识会话对象
}

// ServiceInstance 定义服务实例的基本信息。
type ServiceInstance struct {
	ID        uuid.UUID         `json:"id"`        // 服务实例ID
	Name      string            `json:"name"`      // 服务名称
	Endpoint  string            `json:"endpoint"`  // 服务访问地址，如 "host:port"
	HeartBeat int64             `json:"heartbeat"` // 上次心跳时间戳，单位毫秒
	Zone      string            `json:"zone"`      // 服务所在的可用区或数据中心
	Version   string            `json:"version"`   // 服务版本信息
	Weight    int               `json:"weight"`    // 负载均衡权重
	Tags      []string          `json:"tags"`      // 服务标签列表
	MetaData  map[string]string `json:"metadata"`  // 其他元信息
}

// ServiceSnapshot 定义服务快照信息，用于服务发现和注册。
type ServiceSnapshot struct {
	Name      string             `json:"name"`      // 服务名称
	Instances []*ServiceInstance `json:"instances"` // 服务实例列表
	Revision  int64              `json:"revision"`  // 快照版本号
}
