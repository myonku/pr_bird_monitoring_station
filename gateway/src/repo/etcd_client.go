package repo

import (
	"context"
	"errors"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/concurrency"

	"gateway/src/types"
)

// EtcdClient 提供与 Etcd 交互的常见操作。
type EtcdClient struct {
	client    *clientv3.Client
	opTimeout time.Duration
}

// NewEtcdClient 创建并验证 Etcd 连接。
func NewEtcdClient(cfg *types.EtcdClientConfig) (*EtcdClient, error) {
	if len(cfg.Endpoints) == 0 {
		return nil, errors.New("etcd endpoints are required")
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 5 * time.Second
	}
	if cfg.OpTimeout <= 0 {
		cfg.OpTimeout = 3 * time.Second
	}

	client, err := clientv3.New(clientv3.Config{
		Endpoints:        cfg.Endpoints,
		Username:         cfg.Username,
		Password:         cfg.Password,
		DialTimeout:      cfg.DialTimeout,
		AutoSyncInterval: cfg.AutoSyncInterval,
		TLS:              cfg.TLSConfig,
	})
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.OpTimeout)
	defer cancel()
	if _, err = client.Status(ctx, cfg.Endpoints[0]); err != nil {
		_ = client.Close()
		return nil, err
	}

	return &EtcdClient{client: client, opTimeout: cfg.OpTimeout}, nil
}

// Raw 返回底层 etcd 客户端。
func (c *EtcdClient) Raw() *clientv3.Client {
	return c.client
}

// Close 关闭连接。
func (c *EtcdClient) Close() error {
	if c == nil || c.client == nil {
		return nil
	}
	return c.client.Close()
}

// Ping 探测集群连接健康。
func (c *EtcdClient) Ping(ctx context.Context) error {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	endpoints := c.client.Endpoints()
	if len(endpoints) == 0 {
		return errors.New("no etcd endpoints available")
	}
	_, err := c.client.Status(ctx, endpoints[0])
	return err
}

// Put 写入 key/value。
func (c *EtcdClient) Put(
	ctx context.Context,
	key, value string,
	opts ...clientv3.OpOption,
) (*clientv3.PutResponse, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return c.client.Put(ctx, key, value, opts...)
}

// PutWithTTL 写入带租约的 key/value。
func (c *EtcdClient) PutWithTTL(
	ctx context.Context,
	key, value string,
	ttlSeconds int64,
) (*clientv3.PutResponse, clientv3.LeaseID, error) {
	if ttlSeconds <= 0 {
		return nil, 0, errors.New("ttlSeconds must be > 0")
	}
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()

	leaseResp, err := c.client.Grant(ctx, ttlSeconds)
	if err != nil {
		return nil, 0, err
	}
	putResp, err := c.client.Put(ctx, key, value, clientv3.WithLease(leaseResp.ID))
	if err != nil {
		return nil, 0, err
	}
	return putResp, leaseResp.ID, nil
}

// Get 读取 key。
func (c *EtcdClient) Get(
	ctx context.Context,
	key string,
	opts ...clientv3.OpOption,
) (*clientv3.GetResponse, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return c.client.Get(ctx, key, opts...)
}

// GetOne 读取单 key 字符串值。
func (c *EtcdClient) GetOne(ctx context.Context, key string) (string, bool, error) {
	resp, err := c.Get(ctx, key)
	if err != nil {
		return "", false, err
	}
	if len(resp.Kvs) == 0 {
		return "", false, nil
	}
	return string(resp.Kvs[0].Value), true, nil
}

// GetPrefix 读取前缀下所有键值。
func (c *EtcdClient) GetPrefix(ctx context.Context, prefix string) (map[string]string, error) {
	resp, err := c.Get(ctx, prefix, clientv3.WithPrefix())
	if err != nil {
		return nil, err
	}
	result := make(map[string]string, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		result[string(kv.Key)] = string(kv.Value)
	}
	return result, nil
}

// Delete 删除 key。
func (c *EtcdClient) Delete(
	ctx context.Context,
	key string,
	opts ...clientv3.OpOption,
) (*clientv3.DeleteResponse, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return c.client.Delete(ctx, key, opts...)
}

// DeletePrefix 删除前缀下所有 key。
func (c *EtcdClient) DeletePrefix(ctx context.Context, prefix string) (int64, error) {
	resp, err := c.Delete(ctx, prefix, clientv3.WithPrefix())
	if err != nil {
		return 0, err
	}
	return resp.Deleted, nil
}

// Txn 执行事务。
func (c *EtcdClient) Txn(
	ctx context.Context,
	cmps []clientv3.Cmp,
	thenOps []clientv3.Op,
	elseOps []clientv3.Op,
) (*clientv3.TxnResponse, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()

	txn := c.client.Txn(ctx)
	if len(cmps) > 0 {
		txn = txn.If(cmps...)
	}
	if len(thenOps) > 0 {
		txn = txn.Then(thenOps...)
	}
	if len(elseOps) > 0 {
		txn = txn.Else(elseOps...)
	}
	return txn.Commit()
}

// Watch 监听 key 或前缀变更。
func (c *EtcdClient) Watch(
	ctx context.Context, key string, opts ...clientv3.OpOption) clientv3.WatchChan {
	if ctx == nil {
		ctx = context.Background()
	}
	return c.client.Watch(ctx, key, opts...)
}

// GrantLease 创建租约。
func (c *EtcdClient) GrantLease(ctx context.Context, ttlSeconds int64) (clientv3.LeaseID, error) {
	if ttlSeconds <= 0 {
		return 0, errors.New("ttlSeconds must be > 0")
	}
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	resp, err := c.client.Grant(ctx, ttlSeconds)
	if err != nil {
		return 0, err
	}
	return resp.ID, nil
}

// KeepAlive 对租约做续期。
func (c *EtcdClient) KeepAlive(
	ctx context.Context,
	leaseID clientv3.LeaseID,
) (<-chan *clientv3.LeaseKeepAliveResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	return c.client.KeepAlive(ctx, leaseID)
}

// RevokeLease 撤销租约。
func (c *EtcdClient) RevokeLease(ctx context.Context, leaseID clientv3.LeaseID) error {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	_, err := c.client.Revoke(ctx, leaseID)
	return err
}

// AcquireLock 创建分布式锁，调用方需在结束时 ReleaseLock。
func (c *EtcdClient) AcquireLock(
	ctx context.Context,
	lockName string,
	ttlSeconds int,
) (*concurrency.Session, *concurrency.Mutex, error) {
	if lockName == "" {
		return nil, nil, errors.New("lockName is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if ttlSeconds <= 0 {
		ttlSeconds = 10
	}

	session, err := concurrency.NewSession(
		c.client, concurrency.WithTTL(ttlSeconds), concurrency.WithContext(ctx))
	if err != nil {
		return nil, nil, err
	}

	mutex := concurrency.NewMutex(session, lockName)
	lockCtx, cancel := c.withTimeout(ctx)
	defer cancel()
	if err := mutex.Lock(lockCtx); err != nil {
		_ = session.Close()
		return nil, nil, err
	}
	return session, mutex, nil
}

// ReleaseLock 释放分布式锁。
func (c *EtcdClient) ReleaseLock(
	ctx context.Context, session *concurrency.Session, mutex *concurrency.Mutex) error {
	if session == nil || mutex == nil {
		return nil
	}
	unlockCtx, cancel := c.withTimeout(ctx)
	defer cancel()
	if err := mutex.Unlock(unlockCtx); err != nil {
		_ = session.Close()
		return err
	}
	return session.Close()
}

// EndpointStatus 获取所有 endpoint 状态。
func (c *EtcdClient) EndpointStatus(ctx context.Context) (map[string]*clientv3.StatusResponse, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()

	result := make(map[string]*clientv3.StatusResponse)
	for _, endpoint := range c.client.Endpoints() {
		status, err := c.client.Status(ctx, endpoint)
		if err != nil {
			return nil, err
		}
		result[endpoint] = status
	}
	return result, nil
}

func (c *EtcdClient) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
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
