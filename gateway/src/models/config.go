package models

import (
	"crypto/tls"
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
	return &ProjectConfig{}, nil
}

// Config 定义了认证服务器的整体配置结构体。
type ProjectConfig struct {
	MySQL *MySQLConfig
	Redis *RedisClientConfig
	Etcd  *EtcdClientConfig
	Kafka *KafkaClientConfig
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

// DSNList 返回去空后的连接串列表。
func (c *MySQLConfig) DSNList() []string {
	if c == nil {
		return nil
	}
	result := make([]string, 0, len(c.DSNs)+1)
	for _, dsn := range c.DSNs {
		if dsn != "" {
			result = append(result, dsn)
		}
	}
	if c.DSN != "" {
		result = append(result, c.DSN)
	}
	return result
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
