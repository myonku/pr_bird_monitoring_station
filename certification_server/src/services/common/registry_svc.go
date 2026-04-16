package common

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	commonif "certification_server/src/iface/common"
	commonmodel "certification_server/src/models/common"
	modelsystem "certification_server/src/models/system"
	"certification_server/src/repo"
	"certification_server/src/utils"

	"github.com/google/uuid"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const defaultRegistryMaxStaleWindow = 30 * time.Second

var _ commonif.IRegistryManager = (*RegistryService)(nil)

// RegistryService 基于 Etcd 实现服务注册与发现数据源。
type RegistryService struct {
	etcd      *repo.EtcdClient
	keyRoot   string
	opTimeout time.Duration

	leaseMu      sync.Mutex
	leaseIDs     map[string]clientv3.LeaseID
	leaseCancels map[string]context.CancelFunc
	counter      atomic.Uint64
	maxStale     time.Duration
}

// NewRegistryService 创建注册服务。
func NewRegistryService(
	etcdClient *repo.EtcdClient, keyRoot string, opTimeout time.Duration) commonif.IRegistryManager {

	if keyRoot == "" {
		keyRoot = "bms/services"
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
		maxStale:     defaultRegistryMaxStaleWindow,
	}
}

// Register 注册服务实例。
func (r *RegistryService) Register(instance *commonmodel.ServiceInstance, ttl int64) error {
	if r.etcd == nil {
		return &modelsystem.ErrNilEtcdClient
	}
	if instance.Name == "" || instance.ID == uuid.Nil {
		return &modelsystem.ErrInstanceNameOrIdRequired
	}
	if instance.HeartBeat <= 0 {
		instance.HeartBeat = time.Now().UnixMilli()
	}
	if instance.Weight <= 0 {
		instance.Weight = 1
	}

	r.stopKeepAlive(instance.Name, instance.ID.String())

	payload, err := json.Marshal(instance)
	if err != nil {
		return fmt.Errorf("%w: %v", &modelsystem.ErrRegistryInstanceMarshal, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), r.opTimeout)
	defer cancel()

	key := r.instanceKey(instance.Name, instance.ID.String())
	if ttl > 0 {
		_, leaseID, putErr := r.etcd.PutWithTTL(ctx, key, string(payload), ttl)
		if putErr != nil {
			return putErr
		}
		r.startKeepAlive(instance.Name, instance.ID.String(), leaseID, instance)
		return nil
	}

	_, err = r.etcd.Put(ctx, key, string(payload))
	return err
}

// UnRegister 注销服务实例。
func (r *RegistryService) UnRegister(instance *commonmodel.ServiceInstance) error {
	if r.etcd == nil {
		return &modelsystem.ErrNilEtcdClient
	}
	if instance.Name == "" || instance.ID == uuid.Nil {
		return &modelsystem.ErrInstanceNameOrIdRequired
	}

	key := r.instanceKey(instance.Name, instance.ID.String())
	r.stopKeepAlive(instance.Name, instance.ID.String())

	ctx, cancel := context.WithTimeout(context.Background(), r.opTimeout)
	defer cancel()
	_, err := r.etcd.Delete(ctx, key)
	return err
}

// GetServiceInstances 获取服务实例列表。
func (r *RegistryService) GetServiceInstances(serviceName string) ([]*commonmodel.ServiceInstance, error) {
	if r.etcd == nil {
		return nil, &modelsystem.ErrNilEtcdClient
	}
	if serviceName == "" {
		return nil, &modelsystem.ErrServiceNameRequired
	}

	ctx, cancel := context.WithTimeout(context.Background(), r.opTimeout)
	defer cancel()

	resp, err := r.etcd.Get(ctx, r.servicePrefix(serviceName), clientv3.WithPrefix())
	if err != nil {
		return nil, err
	}

	instances := make([]*commonmodel.ServiceInstance, 0, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		var inst commonmodel.ServiceInstance
		if unmarshalErr := json.Unmarshal(kv.Value, &inst); unmarshalErr != nil {
			continue
		}
		instances = append(instances, &inst)
	}

	sort.Slice(instances, func(i, j int) bool { return instances[i].ID.String() < instances[j].ID.String() })
	return instances, nil
}

// GetServiceSnapShot 获取指定服务快照。
func (r *RegistryService) GetServiceSnapShot(serviceName string) (*commonmodel.ServiceSnapshot, error) {
	if r.etcd == nil {
		return nil, &modelsystem.ErrNilEtcdClient
	}
	if serviceName == "" {
		return nil, &modelsystem.ErrServiceNameRequired
	}

	ctx, cancel := context.WithTimeout(context.Background(), r.opTimeout)
	defer cancel()

	resp, err := r.etcd.Get(ctx, r.servicePrefix(serviceName), clientv3.WithPrefix())
	if err != nil {
		return nil, err
	}

	instances := make([]*commonmodel.ServiceInstance, 0, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		var inst commonmodel.ServiceInstance
		if unmarshalErr := json.Unmarshal(kv.Value, &inst); unmarshalErr != nil {
			continue
		}
		instCopy := inst
		instances = append(instances, &instCopy)
	}

	sort.Slice(instances, func(i, j int) bool { return instances[i].ID.String() < instances[j].ID.String() })

	return &commonmodel.ServiceSnapshot{
		Name:      serviceName,
		Instances: instances,
		Revision:  resp.Header.Revision,
	}, nil
}

// ChooseEndpoint 选择服务实例。
func (d *RegistryService) ChooseEndpoint(
	serviceName string, affinityKey string, requireTags []string) (*commonmodel.ServiceInstance, error) {

	if serviceName == "" {
		return nil, &modelsystem.ErrServiceNameRequired
	}

	instances, err := d.GetServiceInstances(serviceName)
	if err != nil {
		return nil, err
	}
	if len(instances) == 0 {
		return nil, &modelsystem.ErrNoAvaliableInstances
	}

	nowMS := time.Now().UnixMilli()
	alive := make([]*commonmodel.ServiceInstance, 0, len(instances))
	for i := range instances {
		inst := instances[i]
		if inst == nil {
			continue
		}
		if inst.HeartBeat <= 0 {
			continue
		}
		if d.maxStale > 0 && nowMS-inst.HeartBeat > d.maxStale.Milliseconds() {
			continue
		}
		alive = append(alive, inst)
	}
	if len(alive) == 0 {
		return nil, &modelsystem.ErrNoAvaliableInstances
	}

	filtered := utils.FilterByTags(alive, requireTags)
	if len(filtered) == 0 {
		return nil, &modelsystem.ErrNoMatchingTags
	}

	var selected *commonmodel.ServiceInstance
	if affinityKey != "" {
		selected = utils.PickHashAffinity(filtered, affinityKey)
	} else {
		selected = utils.RandomWeighted(filtered)
		if selected == nil {
			idx := int(d.counter.Add(1) - 1)
			selected = utils.PickRoundRobin(filtered, idx)
		}
	}

	if selected == nil || selected.Endpoint == "" {
		return nil, &modelsystem.ErrInvalidInstance
	}
	return selected, nil
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

func (r *RegistryService) startKeepAlive(
	serviceName,
	instanceID string,
	leaseID clientv3.LeaseID,
	instance *commonmodel.ServiceInstance,
) {
	key := r.keepAliveKey(serviceName, instanceID)
	instanceKey := r.instanceKey(serviceName, instanceID)
	instanceTemplate := commonmodel.ServiceInstance{}
	if instance != nil {
		instanceTemplate = *instance
	}

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
			if instanceTemplate.ID != uuid.Nil {
				refresh := instanceTemplate
				refresh.HeartBeat = time.Now().UnixMilli()
				if payload, marshalErr := json.Marshal(&refresh); marshalErr == nil {
					putCtx, putCancel := context.WithTimeout(context.Background(), r.opTimeout)
					_, _ = r.etcd.Put(putCtx, instanceKey, string(payload), clientv3.WithLease(leaseID))
					putCancel()
				}
			}
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
