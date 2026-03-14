package repo

import (
	"context"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/concurrency"

	modelsystem "gateway/src/models/system"
	"gateway/src/utils"
)

// EtcdClient 提供与 Etcd 交互的常见操作。
type EtcdClient struct {
	client    *clientv3.Client
	breaker   *utils.CircuitBreaker
	opTimeout time.Duration
}

// NewEtcdClient 创建并验证 Etcd 连接。
func NewEtcdClient(cfg *modelsystem.EtcdClientConfig) (*EtcdClient, error) {
	if len(cfg.Endpoints) == 0 {
		return nil, &modelsystem.ErrEndpointsRequired
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

	return &EtcdClient{
		client:    client,
		breaker:   utils.NewCircuitBreaker("etcd-client", cfg.CircuitBreaker),
		opTimeout: cfg.OpTimeout,
	}, nil
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
	_, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		endpoints := c.client.Endpoints()
		if len(endpoints) == 0 {
			return nil, &modelsystem.ErrNilEndpoints
		}
		_, runErr := c.client.Status(execCtx, endpoints[0])
		return nil, runErr
	})
	return err
}

// Put 写入 key/value。
func (c *EtcdClient) Put(
	ctx context.Context,
	key, value string,
	opts ...clientv3.OpOption,
) (*clientv3.PutResponse, error) {
	res, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		return c.client.Put(execCtx, key, value, opts...)
	})
	if err != nil {
		return nil, err
	}
	return res.(*clientv3.PutResponse), nil
}

// PutWithTTL 写入带租约的 key/value。
func (c *EtcdClient) PutWithTTL(
	ctx context.Context,
	key, value string,
	ttlSeconds int64,
) (*clientv3.PutResponse, clientv3.LeaseID, error) {
	if ttlSeconds <= 0 {
		return nil, 0, &modelsystem.ErrorNegativeEtcdTTL
	}
	res, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		leaseResp, runErr := c.client.Grant(execCtx, ttlSeconds)
		if runErr != nil {
			return nil, runErr
		}
		putResp, runErr := c.client.Put(execCtx, key, value, clientv3.WithLease(leaseResp.ID))
		if runErr != nil {
			return nil, runErr
		}
		return putWithTTLResult{putResp: putResp, leaseID: leaseResp.ID}, nil
	})
	if err != nil {
		return nil, 0, err
	}
	final := res.(putWithTTLResult)
	return final.putResp, final.leaseID, nil
}

// Get 读取 key。
func (c *EtcdClient) Get(
	ctx context.Context,
	key string,
	opts ...clientv3.OpOption,
) (*clientv3.GetResponse, error) {
	res, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		return c.client.Get(execCtx, key, opts...)
	})
	if err != nil {
		return nil, err
	}
	return res.(*clientv3.GetResponse), nil
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
	res, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		return c.client.Delete(execCtx, key, opts...)
	})
	if err != nil {
		return nil, err
	}
	return res.(*clientv3.DeleteResponse), nil
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
	res, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		txn := c.client.Txn(execCtx)
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
	})
	if err != nil {
		return nil, err
	}
	return res.(*clientv3.TxnResponse), nil
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
		return 0, &modelsystem.ErrorNegativeEtcdTTL
	}
	res, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		return c.client.Grant(execCtx, ttlSeconds)
	})
	if err != nil {
		return 0, err
	}
	return res.(*clientv3.LeaseGrantResponse).ID, nil
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
	_, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		_, runErr := c.client.Revoke(execCtx, leaseID)
		return nil, runErr
	})
	return err
}

// AcquireLock 创建分布式锁，调用方需在结束时 ReleaseLock。
func (c *EtcdClient) AcquireLock(
	ctx context.Context,
	lockName string,
	ttlSeconds int,
) (*concurrency.Session, *concurrency.Mutex, error) {
	if lockName == "" {
		return nil, nil, &modelsystem.ErrLockNameRequired
	}
	if ttlSeconds <= 0 {
		ttlSeconds = 10
	}

	res, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		session, runErr := concurrency.NewSession(
			c.client,
			concurrency.WithTTL(ttlSeconds),
			concurrency.WithContext(execCtx),
		)
		if runErr != nil {
			return nil, runErr
		}

		mutex := concurrency.NewMutex(session, lockName)
		if runErr = mutex.Lock(execCtx); runErr != nil {
			_ = session.Close()
			return nil, runErr
		}

		return acquireLockResult{session: session, mutex: mutex}, nil
	})
	if err != nil {
		return nil, nil, err
	}
	final := res.(acquireLockResult)
	return final.session, final.mutex, nil
}

// ReleaseLock 释放分布式锁。
func (c *EtcdClient) ReleaseLock(
	ctx context.Context, session *concurrency.Session, mutex *concurrency.Mutex) error {
	if session == nil || mutex == nil {
		return nil
	}
	_, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		if runErr := mutex.Unlock(execCtx); runErr != nil {
			_ = session.Close()
			return nil, runErr
		}
		return nil, session.Close()
	})
	return err
}

// EndpointStatus 获取所有 endpoint 状态。
func (c *EtcdClient) EndpointStatus(ctx context.Context) (map[string]*clientv3.StatusResponse, error) {
	res, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		result := make(map[string]*clientv3.StatusResponse)
		for _, endpoint := range c.client.Endpoints() {
			status, runErr := c.client.Status(execCtx, endpoint)
			if runErr != nil {
				return nil, runErr
			}
			result[endpoint] = status
		}
		return result, nil
	})
	if err != nil {
		return nil, err
	}
	return res.(map[string]*clientv3.StatusResponse), nil
}

func (c *EtcdClient) execute(ctx context.Context, fn func(context.Context) (any, error)) (any, error) {
	if c == nil || c.client == nil {
		return nil, &modelsystem.ErrNilEtcdClient
	}
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	if c.breaker != nil {
		return c.breaker.CallWithResult(ctx, fn)
	}
	return fn(ctx)
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

type putWithTTLResult struct {
	putResp *clientv3.PutResponse
	leaseID clientv3.LeaseID
}

type acquireLockResult struct {
	session *concurrency.Session
	mutex   *concurrency.Mutex
}
