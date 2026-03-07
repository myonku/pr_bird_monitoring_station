package models

import (
	"crypto/tls"
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
