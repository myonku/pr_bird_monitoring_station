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

// 项目的全局配置结构体
type ProjectConfig struct {
}

// 限流配置结构体
type RateLimitConfig struct {
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
