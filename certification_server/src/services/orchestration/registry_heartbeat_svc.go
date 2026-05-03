package orchestration

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	commonif "certification_server/src/iface/common"
	commonmodel "certification_server/src/models/common"
	modelsystem "certification_server/src/models/system"
)

// RegistryHeartbeatService 认证中心无凭证注册续期服务。
// 认证中心作为系统权威不需要向其他服务认证，因此只需简单的心跳续期逻辑。
type RegistryHeartbeatService struct {
	runtime            modelsystem.RuntimeConfig
	registryMgr        commonif.IRegistryManager
	instance           *commonmodel.ServiceInstance
	registryTTLSeconds int64
	interval           time.Duration

	mu         sync.Mutex
	registered bool
}

// NewRegistryHeartbeatService 创建认证中心注册续期服务。
func NewRegistryHeartbeatService(
	runtime modelsystem.RuntimeConfig,
	registryMgr commonif.IRegistryManager,
	instance *commonmodel.ServiceInstance,
	registryTTLSeconds int64,
) *RegistryHeartbeatService {
	return &RegistryHeartbeatService{
		runtime:            runtime,
		registryMgr:        registryMgr,
		instance:           instance,
		registryTTLSeconds: registryTTLSeconds,
		interval:           15 * time.Second,
	}
}

// MarkRegistered 标记当前实例已处于服务发现中。
func (s *RegistryHeartbeatService) MarkRegistered() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.registered = true
	s.mu.Unlock()
}

// MarkUnregistered 标记当前实例已退出服务发现。
func (s *RegistryHeartbeatService) MarkUnregistered() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.registered = false
	s.mu.Unlock()
}

// Run 启动周期性心跳续期循环。
func (s *RegistryHeartbeatService) Run(ctx context.Context) {
	if s == nil {
		return
	}
	if err := s.RefreshRegistration(ctx); err != nil {
		log.Printf("registry heartbeat initial refresh failed: %v", err)
	}

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.RefreshRegistration(ctx); err != nil {
				log.Printf("registry heartbeat refresh failed: %v", err)
			}
		}
	}
}

// RefreshRegistration 执行一次注册续期。
func (s *RegistryHeartbeatService) RefreshRegistration(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if s.registryMgr == nil || s.instance == nil {
		return fmt.Errorf("registry manager or instance is nil")
	}

	if !s.isRegistered() {
		log.Printf("stage=registry_not_registered service=%s instance=%s, skipping refresh", s.runtime.ServiceName, s.instance.ID.String())
		return nil
	}

	// 更新心跳时间戳
	s.instance.HeartBeat = time.Now().UnixMilli()

	if err := s.registryMgr.Register(s.instance, s.registryTTLSeconds); err != nil {
		log.Printf("stage=registry_refresh_failed service=%s instance=%s error=%v", s.runtime.ServiceName, s.instance.ID.String(), err)
		return err
	}

	log.Printf("stage=registry_refresh_success service=%s instance=%s endpoint=%s", s.runtime.ServiceName, s.instance.ID.String(), s.instance.Endpoint)
	return nil
}

func (s *RegistryHeartbeatService) isRegistered() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.registered
}
