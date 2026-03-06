package repo

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"gateway/src/types"
)

// RedisClient 提供与Redis交互的常见操作。
type RedisClient struct {
	client     redis.UniversalClient
	opTimeout  time.Duration
	defaultTTL time.Duration
}

// NewRedisClient 创建并验证 Redis 连接。
func NewRedisClient(cfg *types.RedisClientConfig) (*RedisClient, error) {
	if cfg == nil {
		return nil, errors.New("redis config is nil")
	}
	if cfg.OpTimeout <= 0 {
		cfg.OpTimeout = 3 * time.Second
	}
	mode := normalizeRedisMode(cfg.Mode)
	addrs := normalizeRedisAddrs(cfg)

	switch mode {
	case "standalone":
		if len(addrs) == 0 {
			return nil, errors.New("redis addr is required for standalone mode")
		}
		addrs = addrs[:1]
	case "sentinel":
		if len(addrs) == 0 {
			return nil, errors.New("redis addrs are required for sentinel mode")
		}
		if strings.TrimSpace(cfg.MasterName) == "" {
			return nil, errors.New("redis master name is required for sentinel mode")
		}
	case "cluster":
		if len(addrs) == 0 {
			return nil, errors.New("redis addrs are required for cluster mode")
		}
	default:
		return nil, errors.New("unsupported redis mode")
	}

	client := redis.NewUniversalClient(&redis.UniversalOptions{
		Addrs:            addrs,
		MasterName:       cfg.MasterName,
		Username:         cfg.Username,
		Password:         cfg.Password,
		SentinelUsername: cfg.SentinelUsername,
		SentinelPassword: cfg.SentinelPassword,
		DB:               cfg.DB,
		MaxRetries:       cfg.MaxRetries,
		PoolSize:         cfg.PoolSize,
		MinIdleConns:     cfg.MinIdleConns,
		DialTimeout:      cfg.DialTimeout,
		ReadTimeout:      cfg.ReadTimeout,
		WriteTimeout:     cfg.WriteTimeout,
		ReadOnly:         cfg.ReadOnly,
		RouteByLatency:   cfg.RouteByLatency,
		RouteRandomly:    cfg.RouteRandomly,
		TLSConfig:        cfg.TLSConfig,
	})

	ctx, cancel := context.WithTimeout(context.Background(), cfg.OpTimeout)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, err
	}

	return &RedisClient{
		client:     client,
		opTimeout:  cfg.OpTimeout,
		defaultTTL: cfg.DefaultTTL,
	}, nil
}

// Raw 返回底层 redis 客户端，便于执行高级命令。
func (c *RedisClient) Raw() redis.UniversalClient {
	return c.client
}

// Close 关闭连接。
func (c *RedisClient) Close() error {
	if c == nil || c.client == nil {
		return nil
	}
	return c.client.Close()
}

// Ping 探测连接健康。
func (c *RedisClient) Ping(ctx context.Context) error {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return c.client.Ping(ctx).Err()
}

// Set 写入键值。
func (c *RedisClient) Set(ctx context.Context, key string, value any, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = c.defaultTTL
	}
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return c.client.Set(ctx, key, value, ttl).Err()
}

// Get 读取字符串值。
func (c *RedisClient) Get(ctx context.Context, key string) (string, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return c.client.Get(ctx, key).Result()
}

// MGet 批量读取。
func (c *RedisClient) MGet(ctx context.Context, keys ...string) ([]any, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return c.client.MGet(ctx, keys...).Result()
}

// MSet 批量写入。
func (c *RedisClient) MSet(ctx context.Context, kv map[string]any) error {
	if len(kv) == 0 {
		return nil
	}
	args := make([]any, 0, len(kv)*2)
	for k, v := range kv {
		args = append(args, k, v)
	}
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return c.client.MSet(ctx, args...).Err()
}

// Del 删除键。
func (c *RedisClient) Del(ctx context.Context, keys ...string) (int64, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return c.client.Del(ctx, keys...).Result()
}

// Exists 检查键是否存在。
func (c *RedisClient) Exists(ctx context.Context, keys ...string) (int64, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return c.client.Exists(ctx, keys...).Result()
}

// Expire 设置过期时间。
func (c *RedisClient) Expire(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return c.client.Expire(ctx, key, ttl).Result()
}

// TTL 读取剩余过期时间。
func (c *RedisClient) TTL(ctx context.Context, key string) (time.Duration, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return c.client.TTL(ctx, key).Result()
}

// IncrBy 对整数值做增量。
func (c *RedisClient) IncrBy(ctx context.Context, key string, delta int64) (int64, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return c.client.IncrBy(ctx, key, delta).Result()
}

// HSet 批量写入 Hash 字段。
func (c *RedisClient) HSet(ctx context.Context, key string, values map[string]any) (int64, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return c.client.HSet(ctx, key, values).Result()
}

// HGet 读取 Hash 字段。
func (c *RedisClient) HGet(ctx context.Context, key, field string) (string, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return c.client.HGet(ctx, key, field).Result()
}

// HGetAll 读取全部 Hash 字段。
func (c *RedisClient) HGetAll(ctx context.Context, key string) (map[string]string, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return c.client.HGetAll(ctx, key).Result()
}

// HDel 删除 Hash 字段。
func (c *RedisClient) HDel(ctx context.Context, key string, fields ...string) (int64, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return c.client.HDel(ctx, key, fields...).Result()
}

// LPush 从左侧写入列表。
func (c *RedisClient) LPush(ctx context.Context, key string, values ...any) (int64, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return c.client.LPush(ctx, key, values...).Result()
}

// RPush 从右侧写入列表。
func (c *RedisClient) RPush(ctx context.Context, key string, values ...any) (int64, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return c.client.RPush(ctx, key, values...).Result()
}

// LPop 从左侧弹出。
func (c *RedisClient) LPop(ctx context.Context, key string) (string, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return c.client.LPop(ctx, key).Result()
}

// RPop 从右侧弹出。
func (c *RedisClient) RPop(ctx context.Context, key string) (string, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return c.client.RPop(ctx, key).Result()
}

// SAdd 向集合新增成员。
func (c *RedisClient) SAdd(ctx context.Context, key string, members ...any) (int64, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return c.client.SAdd(ctx, key, members...).Result()
}

// SRem 删除集合成员。
func (c *RedisClient) SRem(ctx context.Context, key string, members ...any) (int64, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return c.client.SRem(ctx, key, members...).Result()
}

// SMembers 读取集合全部成员。
func (c *RedisClient) SMembers(ctx context.Context, key string) ([]string, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return c.client.SMembers(ctx, key).Result()
}

// Publish 向频道发布消息。
func (c *RedisClient) Publish(ctx context.Context, channel string, message any) (int64, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return c.client.Publish(ctx, channel, message).Result()
}

// Subscribe 订阅频道，需调用方在不使用时主动 Close。
func (c *RedisClient) Subscribe(ctx context.Context, channels ...string) (*redis.PubSub, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	pubSub := c.client.Subscribe(ctx, channels...)
	if _, err := pubSub.Receive(ctx); err != nil {
		_ = pubSub.Close()
		return nil, err
	}
	return pubSub, nil
}

// Eval 执行 Lua 脚本。
func (c *RedisClient) Eval(ctx context.Context, script string, keys []string, args ...any) (any, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return c.client.Eval(ctx, script, keys, args...).Result()
}

// Do 执行原生命令。
func (c *RedisClient) Do(ctx context.Context, args ...any) (any, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return c.client.Do(ctx, args...).Result()
}

// Scan 扫描键空间。
func (c *RedisClient) Scan(
	ctx context.Context, cursor uint64, match string, count int64) ([]string, uint64, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return c.client.Scan(ctx, cursor, match, count).Result()
}

func (c *RedisClient) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if c.opTimeout <= 0 {
		return ctx, func() {}
	}
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, c.opTimeout)
}

func normalizeRedisMode(mode types.RedisMode) string {
	if strings.TrimSpace(string(mode)) == "" {
		return "standalone"
	}
	return strings.ToLower(strings.TrimSpace(string(mode)))
}

func normalizeRedisAddrs(cfg *types.RedisClientConfig) []string {
	addrs := make([]string, 0, len(cfg.Addrs)+1)
	for _, addr := range cfg.Addrs {
		if strings.TrimSpace(addr) != "" {
			addrs = append(addrs, strings.TrimSpace(addr))
		}
	}
	if strings.TrimSpace(cfg.Addr) != "" {
		addrs = append(addrs, strings.TrimSpace(cfg.Addr))
	}
	return addrs
}
