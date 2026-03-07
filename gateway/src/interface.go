package src

import (
	"context"
	"gateway/src/models"
	"time"

	"github.com/google/uuid"
)

// region 中间件/功能组件接口定义

// 中间件接口定义
type IMiddleWare interface {
}

// endregion

// region 服务接口定义

// 日志服务接口定义
type ILogger interface {
}

// 服务注册接口定义
type IRegistry interface {
	// Register 注册服务实例，ttl 单位为秒。
	Register(instance models.ServiceInstance, ttl int64) error
	// UnRegister 注销服务实例。
	UnRegister(instance models.ServiceInstance) error
	// GetServiceInstances 获取服务实例列表。
	GetServiceInstances(serviceName string) ([]models.ServiceInstance, error)
	// GetServiceSnapShot 获取指定的本地服务快照。
	GetServiceSnapShot(serviceName string) (models.ServiceSnapshot, error)
}

// 服务发现适配器接口定义
type IDiscoveryAdapter interface {
	// ChooseEndpoint 选择服务实例，affinityKey 用于实现会话亲和，requireTags 用于过滤实例。
	ChooseEndpoint(serviceName string, affinityKey string, requireTags []string) (models.ServiceInstance, error)
}

// Session 服务接口定义
type ISessionService interface {
	// SetSession 写入或更新会话信息，ttl 单位为秒。
	SetSession(ctx context.Context, session models.GatewaySession, ttl time.Duration) error
	// GetSession 获取会话信息。
	GetSession(ctx context.Context, sessionID uuid.UUID) (models.GatewaySession, error)
	// DeleteSession 删除会话。
	DeleteSession(ctx context.Context, sessionID uuid.UUID) error
	// 获取会话剩余 TTL，单位为秒。
	TTL(ctx context.Context, sessionID uuid.UUID) (time.Duration, error)
	// RefreshSession 刷新会话 TTL，单位为秒。
	RefreshSession(ctx context.Context, sessionID uuid.UUID, ttl time.Duration) error
}

// endregion
