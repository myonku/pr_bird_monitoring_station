package repo

import (
	"context"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"gateway/src/models"
	"gateway/src/utils"
)

// RedisClient 提供与Redis交互的常见操作。
type RedisClient struct {
	client     redis.UniversalClient
	breaker    *utils.CircuitBreaker
	opTimeout  time.Duration
	defaultTTL time.Duration
}

// NewRedisClient 创建并验证 Redis 连接。
func NewRedisClient(cfg *models.RedisClientConfig) (*RedisClient, error) {
	if cfg == nil {
		return nil, &models.ErrNoConfig
	}
	if cfg.OpTimeout <= 0 {
		cfg.OpTimeout = 3 * time.Second
	}
	mode := normalizeRedisMode(cfg.Mode)
	addrs := normalizeRedisAddrs(cfg)

	switch mode {
	case "standalone":
		if len(addrs) == 0 {
			return nil, &models.ErrAddrRequired
		}
		addrs = addrs[:1]
	case "sentinel":
		if len(addrs) == 0 {
			return nil, &models.ErrAddrRequired
		}
		if strings.TrimSpace(cfg.MasterName) == "" {
			return nil, &models.ErrMasterNameRequired
		}
	case "cluster":
		if len(addrs) == 0 {
			return nil, &models.ErrAddrRequired
		}
	default:
		return nil, &models.ErrorUnsupportedMode
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
		breaker:    utils.NewCircuitBreaker("redis-client", cfg.CircuitBreaker),
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
	_, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		execCtx, cancel := c.withTimeout(execCtx)
		defer cancel()
		return nil, c.client.Ping(execCtx).Err()
	})
	return err
}

// Set 写入键值。
func (c *RedisClient) Set(ctx context.Context, key string, value any, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = c.defaultTTL
	}
	_, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		execCtx, cancel := c.withTimeout(execCtx)
		defer cancel()
		return nil, c.client.Set(execCtx, key, value, ttl).Err()
	})
	return err
}

// Get 读取字符串值。
func (c *RedisClient) Get(ctx context.Context, key string) (string, error) {
	res, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		execCtx, cancel := c.withTimeout(execCtx)
		defer cancel()
		return c.client.Get(execCtx, key).Result()
	})
	if err != nil {
		return "", err
	}
	return res.(string), nil
}

// MGet 批量读取。
func (c *RedisClient) MGet(ctx context.Context, keys ...string) ([]any, error) {
	res, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		execCtx, cancel := c.withTimeout(execCtx)
		defer cancel()
		return c.client.MGet(execCtx, keys...).Result()
	})
	if err != nil {
		return nil, err
	}
	return res.([]any), nil
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
	_, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		execCtx, cancel := c.withTimeout(execCtx)
		defer cancel()
		return nil, c.client.MSet(execCtx, args...).Err()
	})
	return err
}

// Del 删除键。
func (c *RedisClient) Del(ctx context.Context, keys ...string) (int64, error) {
	res, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		execCtx, cancel := c.withTimeout(execCtx)
		defer cancel()
		return c.client.Del(execCtx, keys...).Result()
	})
	if err != nil {
		return 0, err
	}
	return res.(int64), nil
}

// Exists 检查键是否存在。
func (c *RedisClient) Exists(ctx context.Context, keys ...string) (int64, error) {
	res, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		execCtx, cancel := c.withTimeout(execCtx)
		defer cancel()
		return c.client.Exists(execCtx, keys...).Result()
	})
	if err != nil {
		return 0, err
	}
	return res.(int64), nil
}

// Expire 设置过期时间。
func (c *RedisClient) Expire(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	res, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		execCtx, cancel := c.withTimeout(execCtx)
		defer cancel()
		return c.client.Expire(execCtx, key, ttl).Result()
	})
	if err != nil {
		return false, err
	}
	return res.(bool), nil
}

// TTL 读取剩余过期时间。
func (c *RedisClient) TTL(ctx context.Context, key string) (time.Duration, error) {
	res, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		execCtx, cancel := c.withTimeout(execCtx)
		defer cancel()
		return c.client.TTL(execCtx, key).Result()
	})
	if err != nil {
		return 0, err
	}
	return res.(time.Duration), nil
}

// IncrBy 对整数值做增量。
func (c *RedisClient) IncrBy(ctx context.Context, key string, delta int64) (int64, error) {
	res, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		execCtx, cancel := c.withTimeout(execCtx)
		defer cancel()
		return c.client.IncrBy(execCtx, key, delta).Result()
	})
	if err != nil {
		return 0, err
	}
	return res.(int64), nil
}

// HSet 批量写入 Hash 字段。
func (c *RedisClient) HSet(ctx context.Context, key string, values map[string]any) (int64, error) {
	res, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		execCtx, cancel := c.withTimeout(execCtx)
		defer cancel()
		return c.client.HSet(execCtx, key, values).Result()
	})
	if err != nil {
		return 0, err
	}
	return res.(int64), nil
}

// HGet 读取 Hash 字段。
func (c *RedisClient) HGet(ctx context.Context, key, field string) (string, error) {
	res, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		execCtx, cancel := c.withTimeout(execCtx)
		defer cancel()
		return c.client.HGet(execCtx, key, field).Result()
	})
	if err != nil {
		return "", err
	}
	return res.(string), nil
}

// HGetAll 读取全部 Hash 字段。
func (c *RedisClient) HGetAll(ctx context.Context, key string) (map[string]string, error) {
	res, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		execCtx, cancel := c.withTimeout(execCtx)
		defer cancel()
		return c.client.HGetAll(execCtx, key).Result()
	})
	if err != nil {
		return nil, err
	}
	return res.(map[string]string), nil
}

// HDel 删除 Hash 字段。
func (c *RedisClient) HDel(ctx context.Context, key string, fields ...string) (int64, error) {
	res, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		execCtx, cancel := c.withTimeout(execCtx)
		defer cancel()
		return c.client.HDel(execCtx, key, fields...).Result()
	})
	if err != nil {
		return 0, err
	}
	return res.(int64), nil
}

// LPush 从左侧写入列表。
func (c *RedisClient) LPush(ctx context.Context, key string, values ...any) (int64, error) {
	res, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		execCtx, cancel := c.withTimeout(execCtx)
		defer cancel()
		return c.client.LPush(execCtx, key, values...).Result()
	})
	if err != nil {
		return 0, err
	}
	return res.(int64), nil
}

// RPush 从右侧写入列表。
func (c *RedisClient) RPush(ctx context.Context, key string, values ...any) (int64, error) {
	res, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		execCtx, cancel := c.withTimeout(execCtx)
		defer cancel()
		return c.client.RPush(execCtx, key, values...).Result()
	})
	if err != nil {
		return 0, err
	}
	return res.(int64), nil
}

// LPop 从左侧弹出。
func (c *RedisClient) LPop(ctx context.Context, key string) (string, error) {
	res, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		execCtx, cancel := c.withTimeout(execCtx)
		defer cancel()
		return c.client.LPop(execCtx, key).Result()
	})
	if err != nil {
		return "", err
	}
	return res.(string), nil
}

// RPop 从右侧弹出。
func (c *RedisClient) RPop(ctx context.Context, key string) (string, error) {
	res, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		execCtx, cancel := c.withTimeout(execCtx)
		defer cancel()
		return c.client.RPop(execCtx, key).Result()
	})
	if err != nil {
		return "", err
	}
	return res.(string), nil
}

// SAdd 向集合新增成员。
func (c *RedisClient) SAdd(ctx context.Context, key string, members ...any) (int64, error) {
	res, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		execCtx, cancel := c.withTimeout(execCtx)
		defer cancel()
		return c.client.SAdd(execCtx, key, members...).Result()
	})
	if err != nil {
		return 0, err
	}
	return res.(int64), nil
}

// SRem 删除集合成员。
func (c *RedisClient) SRem(ctx context.Context, key string, members ...any) (int64, error) {
	res, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		execCtx, cancel := c.withTimeout(execCtx)
		defer cancel()
		return c.client.SRem(execCtx, key, members...).Result()
	})
	if err != nil {
		return 0, err
	}
	return res.(int64), nil
}

// SMembers 读取集合全部成员。
func (c *RedisClient) SMembers(ctx context.Context, key string) ([]string, error) {
	res, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		execCtx, cancel := c.withTimeout(execCtx)
		defer cancel()
		return c.client.SMembers(execCtx, key).Result()
	})
	if err != nil {
		return nil, err
	}
	return res.([]string), nil
}

// Publish 向频道发布消息。
func (c *RedisClient) Publish(ctx context.Context, channel string, message any) (int64, error) {
	res, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		execCtx, cancel := c.withTimeout(execCtx)
		defer cancel()
		return c.client.Publish(execCtx, channel, message).Result()
	})
	if err != nil {
		return 0, err
	}
	return res.(int64), nil
}

// Subscribe 订阅频道，需调用方在不使用时主动 Close。
func (c *RedisClient) Subscribe(ctx context.Context, channels ...string) (*redis.PubSub, error) {
	res, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		execCtx, cancel := c.withTimeout(execCtx)
		defer cancel()
		pubSub := c.client.Subscribe(execCtx, channels...)
		if _, receiveErr := pubSub.Receive(execCtx); receiveErr != nil {
			_ = pubSub.Close()
			return nil, receiveErr
		}
		return pubSub, nil
	})
	if err != nil {
		return nil, err
	}
	return res.(*redis.PubSub), nil
}

// Eval 执行 Lua 脚本。
func (c *RedisClient) Eval(ctx context.Context, script string, keys []string, args ...any) (any, error) {
	return c.execute(ctx, func(execCtx context.Context) (any, error) {
		execCtx, cancel := c.withTimeout(execCtx)
		defer cancel()
		return c.client.Eval(execCtx, script, keys, args...).Result()
	})
}

// Do 执行原生命令。
func (c *RedisClient) Do(ctx context.Context, args ...any) (any, error) {
	return c.execute(ctx, func(execCtx context.Context) (any, error) {
		execCtx, cancel := c.withTimeout(execCtx)
		defer cancel()
		return c.client.Do(execCtx, args...).Result()
	})
}

// Scan 扫描键空间。
func (c *RedisClient) Scan(
	ctx context.Context, cursor uint64, match string, count int64) ([]string, uint64, error) {
	res, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		execCtx, cancel := c.withTimeout(execCtx)
		defer cancel()
		keys, nextCursor, runErr := c.client.Scan(execCtx, cursor, match, count).Result()
		if runErr != nil {
			return nil, runErr
		}
		return scanResult{keys: keys, cursor: nextCursor}, nil
	})
	if err != nil {
		return nil, 0, err
	}
	final := res.(scanResult)
	return final.keys, final.cursor, nil
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

func normalizeRedisMode(mode models.RedisMode) string {
	if strings.TrimSpace(string(mode)) == "" {
		return "standalone"
	}
	return strings.ToLower(strings.TrimSpace(string(mode)))
}

func normalizeRedisAddrs(cfg *models.RedisClientConfig) []string {
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

func (c *RedisClient) execute(ctx context.Context, fn func(context.Context) (any, error)) (any, error) {
	if c != nil && c.breaker != nil {
		return c.breaker.CallWithResult(ctx, fn)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return fn(ctx)
}

type scanResult struct {
	keys   []string
	cursor uint64
}
