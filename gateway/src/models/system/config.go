package system

import (
	"crypto/tls"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"
)

type RedisMode string

const (
	RedisModeStandalone RedisMode = "standalone"
	RedisModeSentinel   RedisMode = "sentinel"
	RedisModeCluster    RedisMode = "cluster"
)

// 加载全局配置的函数
func LoadConfig(cfg_path string) (*ProjectConfig, error) {
	return loadProjectConfig(cfg_path)
}

// Config 定义了认证服务器的整体配置结构体。
type ProjectConfig struct {
	MySQL *MySQLConfig
	Redis *RedisClientConfig
	Etcd  *EtcdClientConfig
	Kafka *KafkaClientConfig

	InternalAssertion *InternalAssertionConfig
	SecretKey         *SecretKeyConfig
}

// SecretKeyConfig 定义后端本地密钥装载配置。
type SecretKeyConfig struct {
	Enabled bool

	SecretDir   string
	ActiveKeyID string

	OwnerType    string
	EntityType   string
	EntityID     string
	EntityName   string
	ServiceID    string
	ServiceName  string
	InstanceID   string
	InstanceName string

	KeyExchangeAlgorithm string
	SignatureAlgorithm   string

	PublicKeyRef  string
	PrivateKeyRef string
}

// Normalized 返回包含默认值的密钥装载配置快照。
func (c *SecretKeyConfig) Normalized(defaultEntityID string) SecretKeyConfig {
	if c == nil {
		entityID := strings.TrimSpace(defaultEntityID)
		return SecretKeyConfig{
			Enabled:              false,
			SecretDir:            "secret_keys",
			OwnerType:            "service",
			EntityType:           "service",
			EntityID:             entityID,
			EntityName:           entityID,
			ServiceID:            entityID,
			ServiceName:          entityID,
			KeyExchangeAlgorithm: "ecdhe_p256",
		}
	}

	normalized := *c
	normalized.SecretDir = strings.TrimSpace(normalized.SecretDir)
	if normalized.SecretDir == "" {
		normalized.SecretDir = "secret_keys"
	}
	normalized.ActiveKeyID = strings.TrimSpace(normalized.ActiveKeyID)
	normalized.OwnerType = strings.ToLower(strings.TrimSpace(normalized.OwnerType))
	if normalized.OwnerType == "" {
		normalized.OwnerType = "service"
	}
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
	normalized.ServiceID = strings.TrimSpace(normalized.ServiceID)
	if normalized.ServiceID == "" {
		normalized.ServiceID = normalized.EntityID
	}
	normalized.ServiceName = strings.TrimSpace(normalized.ServiceName)
	if normalized.ServiceName == "" {
		normalized.ServiceName = normalized.EntityName
	}
	normalized.InstanceID = strings.TrimSpace(normalized.InstanceID)
	normalized.InstanceName = strings.TrimSpace(normalized.InstanceName)
	normalized.KeyExchangeAlgorithm = strings.ToLower(strings.TrimSpace(normalized.KeyExchangeAlgorithm))
	if normalized.KeyExchangeAlgorithm == "" {
		normalized.KeyExchangeAlgorithm = "ecdhe_p256"
	}
	normalized.SignatureAlgorithm = strings.ToLower(strings.TrimSpace(normalized.SignatureAlgorithm))
	normalized.PublicKeyRef = strings.TrimSpace(normalized.PublicKeyRef)
	normalized.PrivateKeyRef = strings.TrimSpace(normalized.PrivateKeyRef)

	return normalized
}

// InternalAssertionConfig 定义网关内部断言签发与注入配置。
type InternalAssertionConfig struct {
	Enabled bool

	HeaderName string
	TTLSeconds int64

	Issuer             string
	SignatureAlgorithm string
}

// Normalized 返回包含默认值的配置快照。
func (c *InternalAssertionConfig) Normalized() InternalAssertionConfig {
	if c == nil {
		return InternalAssertionConfig{
			Enabled:    false,
			HeaderName: "x-internal-assertion",
			TTLSeconds: 10,
		}
	}

	normalized := *c
	if normalized.HeaderName == "" {
		normalized.HeaderName = "x-internal-assertion"
	}
	if normalized.TTLSeconds <= 0 {
		normalized.TTLSeconds = 10
	}

	return normalized
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

// KafkaClientConfig 定义 KafkaClient 的连接参数。
type KafkaClientConfig struct {
	Brokers      []string
	ClientID     string
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	BatchTimeout time.Duration
	RequiredAcks kafka.RequiredAcks
	OpTimeout    time.Duration
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
