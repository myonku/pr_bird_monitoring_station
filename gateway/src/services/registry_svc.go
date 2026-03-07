package services

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"gateway/src"
	"gateway/src/models"
	"gateway/src/repo"

	"github.com/google/uuid"
	clientv3 "go.etcd.io/etcd/client/v3"
)

var _ src.IRegistry = (*RegistryService)(nil)

// RegistryService 基于 Etcd 实现服务注册与发现数据源。
type RegistryService struct {
	etcd      *repo.EtcdClient
	keyRoot   string
	opTimeout time.Duration

	leaseMu      sync.Mutex
	leaseIDs     map[string]clientv3.LeaseID
	leaseCancels map[string]context.CancelFunc
}

// NewRegistryService 创建注册服务。
func NewRegistryService(
	etcdClient *repo.EtcdClient, keyRoot string, opTimeout time.Duration) src.IRegistry {

	if keyRoot == "" {
		keyRoot = "gateway/registry"
	}
	if opTimeout <= 0 {
		opTimeout = 3 * time.Second
	}
	return &RegistryService{
		etcd:         etcdClient,
		keyRoot:      strings.Trim(keyRoot, "/"),
		opTimeout:    opTimeout,
		leaseIDs:     make(map[string]clientv3.LeaseID),
		leaseCancels: make(map[string]context.CancelFunc),
	}
}

// Register 注册服务实例。
func (r *RegistryService) Register(instance models.ServiceInstance, ttl int64) error {
	if r.etcd == nil {
		return &models.ErrNilEtcdClient
	}
	if instance.Name == "" || instance.ID == uuid.Nil {
		return &models.ErrInstanceNameOrIdRequired
	}

	r.stopKeepAlive(instance.Name, instance.ID.String())

	payload, err := json.Marshal(instance)
	if err != nil {
		return fmt.Errorf("marshal instance: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), r.opTimeout)
	defer cancel()

	key := r.instanceKey(instance.Name, instance.ID.String())
	if ttl > 0 {
		_, leaseID, putErr := r.etcd.PutWithTTL(ctx, key, string(payload), ttl)
		if putErr != nil {
			return putErr
		}
		r.startKeepAlive(instance.Name, instance.ID.String(), leaseID)
		return nil
	}

	_, err = r.etcd.Put(ctx, key, string(payload))
	return err
}

// UnRegister 注销服务实例。
func (r *RegistryService) UnRegister(instance models.ServiceInstance) error {
	if r.etcd == nil {
		return &models.ErrNilEtcdClient
	}
	if instance.Name == "" || instance.ID == uuid.Nil {
		return &models.ErrInstanceNameOrIdRequired
	}

	key := r.instanceKey(instance.Name, instance.ID.String())
	r.stopKeepAlive(instance.Name, instance.ID.String())

	ctx, cancel := context.WithTimeout(context.Background(), r.opTimeout)
	defer cancel()
	_, err := r.etcd.Delete(ctx, key)
	return err
}

// GetServiceInstances 获取服务实例列表。
func (r *RegistryService) GetServiceInstances(serviceName string) ([]models.ServiceInstance, error) {
	if r.etcd == nil {
		return nil, &models.ErrNilEtcdClient
	}
	if serviceName == "" {
		return nil, &models.ErrServiceNameRequired
	}

	ctx, cancel := context.WithTimeout(context.Background(), r.opTimeout)
	defer cancel()

	resp, err := r.etcd.Get(ctx, r.servicePrefix(serviceName), clientv3.WithPrefix())
	if err != nil {
		return nil, err
	}

	instances := make([]models.ServiceInstance, 0, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		var inst models.ServiceInstance
		if unmarshalErr := json.Unmarshal(kv.Value, &inst); unmarshalErr != nil {
			continue
		}
		instances = append(instances, inst)
	}

	sort.Slice(instances, func(i, j int) bool { return instances[i].ID.String() < instances[j].ID.String() })
	return instances, nil
}

// GetServiceSnapShot 获取指定服务快照。
func (r *RegistryService) GetServiceSnapShot(serviceName string) (models.ServiceSnapshot, error) {
	if r.etcd == nil {
		return models.ServiceSnapshot{}, &models.ErrNilEtcdClient
	}
	if serviceName == "" {
		return models.ServiceSnapshot{}, &models.ErrServiceNameRequired
	}

	ctx, cancel := context.WithTimeout(context.Background(), r.opTimeout)
	defer cancel()

	resp, err := r.etcd.Get(ctx, r.servicePrefix(serviceName), clientv3.WithPrefix())
	if err != nil {
		return models.ServiceSnapshot{}, err
	}

	instances := make([]*models.ServiceInstance, 0, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		var inst models.ServiceInstance
		if unmarshalErr := json.Unmarshal(kv.Value, &inst); unmarshalErr != nil {
			continue
		}
		instCopy := inst
		instances = append(instances, &instCopy)
	}

	sort.Slice(instances, func(i, j int) bool { return instances[i].ID.String() < instances[j].ID.String() })

	return models.ServiceSnapshot{
		Name:      serviceName,
		Instances: instances,
		Revision:  resp.Header.Revision,
	}, nil
}

func (r *RegistryService) servicePrefix(serviceName string) string {
	return fmt.Sprintf("/%s/%s/", r.keyRoot, serviceName)
}

func (r *RegistryService) instanceKey(serviceName, instanceID string) string {
	return fmt.Sprintf("/%s/%s/%s", r.keyRoot, serviceName, instanceID)
}

func (r *RegistryService) keepAliveKey(serviceName, instanceID string) string {
	return serviceName + "::" + instanceID
}

func (r *RegistryService) startKeepAlive(serviceName, instanceID string, leaseID clientv3.LeaseID) {
	key := r.keepAliveKey(serviceName, instanceID)

	r.leaseMu.Lock()
	if oldCancel, ok := r.leaseCancels[key]; ok {
		oldCancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.leaseIDs[key] = leaseID
	r.leaseCancels[key] = cancel
	r.leaseMu.Unlock()

	ch, err := r.etcd.KeepAlive(ctx, leaseID)
	if err != nil {
		cancel()
		r.leaseMu.Lock()
		delete(r.leaseIDs, key)
		delete(r.leaseCancels, key)
		r.leaseMu.Unlock()
		return
	}

	go func(k string, c <-chan *clientv3.LeaseKeepAliveResponse) {
		for range c {
		}
		r.leaseMu.Lock()
		delete(r.leaseIDs, k)
		delete(r.leaseCancels, k)
		r.leaseMu.Unlock()
	}(key, ch)
}

func (r *RegistryService) stopKeepAlive(serviceName, instanceID string) {
	key := r.keepAliveKey(serviceName, instanceID)

	r.leaseMu.Lock()
	leaseID, hasLease := r.leaseIDs[key]
	cancel, hasCancel := r.leaseCancels[key]
	delete(r.leaseIDs, key)
	delete(r.leaseCancels, key)
	r.leaseMu.Unlock()

	if hasCancel {
		cancel()
	}
	if hasLease {
		ctx, c := context.WithTimeout(context.Background(), r.opTimeout)
		_ = r.etcd.RevokeLease(ctx, leaseID)
		c()
	}
}
