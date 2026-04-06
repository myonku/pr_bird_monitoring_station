package system

import (
	"crypto/tls"
	"strings"
	"time"
)

type RedisMode string

const (
	RedisModeStandalone RedisMode = "standalone"
	RedisModeSentinel   RedisMode = "sentinel"
	RedisModeCluster    RedisMode = "cluster"
)

// Config 定义了认证服务器的整体配置结构体。
type ProjectConfig struct {
	MySQL   *MySQLConfig
	Redis   *RedisClientConfig
	Etcd    *EtcdClientConfig
	Runtime *RuntimeConfig
	Auth    *AuthConfig
}

// RuntimeConfig 定义服务本体运行时标识配置。
type RuntimeConfig struct {
	EntityType   string
	EntityID     string
	EntityName   string
	InstanceID   string
	InstanceName string
}

// Normalized 返回包含默认值的运行时标识配置快照。
func (c *RuntimeConfig) Normalized(defaultEntityID string) RuntimeConfig {
	if c == nil {
		entityID := strings.TrimSpace(defaultEntityID)
		return RuntimeConfig{
			EntityType: "service",
			EntityID:   entityID,
			EntityName: entityID,
		}
	}

	normalized := *c
	normalized.EntityType = strings.ToLower(strings.TrimSpace(normalized.EntityType))
	if normalized.EntityType == "" {
		normalized.EntityType = "service"
	}
	normalized.EntityID = strings.TrimSpace(normalized.EntityID)
	if normalized.EntityID == "" {
		normalized.EntityID = strings.TrimSpace(defaultEntityID)
	}
	normalized.EntityName = strings.TrimSpace(normalized.EntityName)
	if normalized.EntityName == "" {
		normalized.EntityName = normalized.EntityID
	}
	normalized.InstanceID = strings.TrimSpace(normalized.InstanceID)
	normalized.InstanceName = strings.TrimSpace(normalized.InstanceName)

	return normalized
}

// AuthConfig 定义认证相关配置。
// 根据全局约束，密钥配置仅保留目录与 active_key_id。
type AuthConfig struct {
	SecretKeyDir string
	ActiveKeyID  string
}

// Normalized 返回包含默认值的认证配置快照。
func (c *AuthConfig) Normalized() AuthConfig {
	if c == nil {
		return AuthConfig{SecretKeyDir: "secret_keys"}
	}

	normalized := *c
	normalized.SecretKeyDir = strings.TrimSpace(normalized.SecretKeyDir)
	if normalized.SecretKeyDir == "" {
		normalized.SecretKeyDir = "secret_keys"
	}
	normalized.ActiveKeyID = strings.TrimSpace(normalized.ActiveKeyID)
	return normalized
}

// SecretKeyStartupParams 是启动期注入到密钥服务的参数快照。
// 仅由 main 在读取配置后构建，后续在主流程按参数传递。
type SecretKeyStartupParams struct {
	SecretKeyDir string
	ActiveKeyID  string

	EntityType   string
	EntityID     string
	EntityName   string
	InstanceID   string
	InstanceName string
}

// BuildSecretKeyStartupParams 从 ProjectConfig 构建密钥服务启动参数。
func (c *ProjectConfig) BuildSecretKeyStartupParams(defaultEntityID string) SecretKeyStartupParams {
	var runtimeCfg *RuntimeConfig
	var authCfg *AuthConfig
	if c != nil {
		runtimeCfg = c.Runtime
		authCfg = c.Auth
	}

	runtime := runtimeCfg.Normalized(defaultEntityID)
	auth := authCfg.Normalized()

	return SecretKeyStartupParams{
		SecretKeyDir: auth.SecretKeyDir,
		ActiveKeyID:  auth.ActiveKeyID,
		EntityType:   runtime.EntityType,
		EntityID:     runtime.EntityID,
		EntityName:   runtime.EntityName,
		InstanceID:   runtime.InstanceID,
		InstanceName: runtime.InstanceName,
	}
}

// EtcdClientConfig 定义 EtcdClient 的连接参数。
type EtcdClientConfig struct {
	Endpoints        []string
	Username         string
	Password         string
	DialTimeout      time.Duration
	AutoSyncInterval time.Duration
	OpTimeout        time.Duration
	TLSConfig        *tls.Config
	CircuitBreaker   *CircuitBreakerConfig
}

// MySQLConfig 定义 MySQL 基础客户端连接参数。
type MySQLConfig struct {
	// DSN 为单连接串，兼容简单场景。
	DSN string
	// DSNs 为多实例连接串列表，按顺序探活。
	DSNs            []string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
	OpTimeout       time.Duration
	CircuitBreaker  *CircuitBreakerConfig
}

// RedisClientConfig 定义 RedisClient 的连接参数。
type RedisClientConfig struct {
	// Mode 支持: standalone / sentinel / cluster，默认 standalone。
	Mode RedisMode
	// Addr 为单机模式地址，兼容旧配置。
	Addr string
	// Addrs 为多节点地址，cluster/sentinel 模式使用该字段。
	Addrs []string
	// MasterName 在 sentinel 模式下必填。
	MasterName string
	Username   string
	Password   string
	// SentinelUsername/SentinelPassword 用于 Sentinel 节点认证。
	SentinelUsername string
	SentinelPassword string
	DB               int
	MaxRetries       int
	PoolSize         int
	MinIdleConns     int
	DialTimeout      time.Duration
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration
	ReadOnly         bool
	RouteByLatency   bool
	RouteRandomly    bool
	OpTimeout        time.Duration
	DefaultTTL       time.Duration
	TLSConfig        *tls.Config
	// CircuitBreaker 为 Redis 客户端熔断配置，可选。
	CircuitBreaker *CircuitBreakerConfig
}

// CircuitBreakerConfig 定义熔断器配置参数。
type CircuitBreakerConfig struct {
	// FailureThreshold 触发熔断的连续失败次数。
	FailureThreshold int
	// SuccessThreshold 熔断器半开状态下允许的连续成功次数。
	RecoveryTimeout time.Duration
	// HalfOpenMaxCalls 半开状态下允许的最大调用次数，超过后继续熔断。
	HalfOpenMaxCalls int
}
