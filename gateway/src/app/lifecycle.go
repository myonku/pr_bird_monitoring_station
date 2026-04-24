package app

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	commonif "gateway/src/iface/common"
	commonmodel "gateway/src/models/common"
	modelsystem "gateway/src/models/system"
	"gateway/src/repo"
	authcontrolsvc "gateway/src/services/authcontrol"
	commonsvc "gateway/src/services/common"
	communicationsvc "gateway/src/services/communication"
	gatewayhttp "gateway/src/services/http"
	orchestrationsvc "gateway/src/services/orchestration"

	"github.com/google/uuid"
)

const (
	defaultGatewayConfigPath  = "settings.toml"
	defaultGatewayEtcdAddress = "127.0.0.1:2379"
	defaultGatewayRegistryTTL = int64(30)
	defaultAuthAuthorityName  = "certification_server"
)

// Run 启动 gateway 最小生命周期：配置 -> 依赖 -> bootstrap占位 -> 注册 -> 最小HTTP运行。
func Run() error {
	cfg, err := modelsystem.LoadConfig(defaultGatewayConfigPath)
	if err != nil {
		return err
	}

	runtimeCfg := cfg.Runtime.Normalized("gateway")
	log.Printf("stage=config_loaded service=%s run_mode=%s", runtimeCfg.ServiceName, runtimeCfg.RunMode)

	etcdCfg := resolveGatewayEtcdConfig(cfg)
	etcdClient, err := repo.NewEtcdClient(etcdCfg)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := etcdClient.Close(); closeErr != nil {
			log.Printf("gateway etcd close failed: %v", closeErr)
		}
	}()

	var redisClient *repo.RedisClient
	if cfg.Redis != nil {
		redisClient, err = repo.NewRedisClient(cfg.Redis)
		if err != nil {
			return err
		}
		defer func() {
			if closeErr := redisClient.Close(); closeErr != nil {
				log.Printf("gateway redis close failed: %v", closeErr)
			}
		}()
	}

	registrySvc := commonsvc.NewRegistryService(etcdClient, "", 0)
	var localCredentialMgr commonif.ILocalCredentialManager
	if redisClient != nil {
		localCredentialMgr = commonsvc.NewLocalCredentialService(redisClient, "")
	}

	policySnapshotMgr := commonsvc.NewPolicySnapshotService("gateway-default", string(runtimeCfg.RunMode))
	serviceResolver := commonsvc.NewServiceResolverService(registrySvc, policySnapshotMgr, defaultAuthAuthorityName)
	routingPipeline := communicationsvc.NewRoutingPayloadPipelineService(serviceResolver)
	authControl := authcontrolsvc.NewGatewayAuthControlService(runtimeCfg.RunMode, serviceResolver, nil, nil)
	trafficStation := communicationsvc.NewTrafficStationService(routingPipeline, authControl)
	log.Printf("stage=dependencies_initialized service=%s", runtimeCfg.ServiceName)

	var startupParams modelsystem.SecretKeyStartupParams
	var bootstrapCoordinator *orchestrationsvc.BootstrapCoordinatorService
	resolvedActiveKeyID := ""
	if runtimeCfg.RunMode == modelsystem.RuntimeRunModeNoAuth {
		log.Printf("stage=bootstrap_skipped_or_ready service=%s mode=no_auth", runtimeCfg.ServiceName)
	} else {
		secretKeySvc, resolvedStartupParams, err := commonsvc.NewSecretKeyServiceFromProjectConfig(cfg, nil, nil)
		if err != nil {
			return err
		}
		startupParams = resolvedStartupParams
		bootstrapOrchestrator := orchestrationsvc.NewBootstrapStartupOrchestratorService(
			localCredentialMgr,
			secretKeySvc,
			trafficStation,
			defaultAuthAuthorityName,
		)
		bootstrapCoordinator = orchestrationsvc.NewBootstrapCoordinatorService(
			runtimeCfg,
			startupParams,
			localCredentialMgr,
			bootstrapOrchestrator,
			nil,
			defaultAuthAuthorityName,
		)
		snapshot, err := bootstrapCoordinator.EnsureModuleReady(context.Background())
		if err != nil {
			return err
		}
		if snapshot != nil {
			resolvedActiveKeyID = snapshot.ActiveCommKeyID
		}
	}

	instance := buildGatewayInstance(runtimeCfg, resolvedActiveKeyID)
	log.Printf("stage=registry_register_attempt service=%s instance=%s", instance.Name, instance.ID.String())
	if err = registrySvc.Register(instance, defaultGatewayRegistryTTL); err != nil {
		return err
	}
	log.Printf("stage=registry_register_success service=%s instance=%s endpoint=%s", instance.Name, instance.ID.String(), instance.Endpoint)

	var credentialSupervisor *orchestrationsvc.CredentialDiscoverySupervisorService
	if runtimeCfg.RunMode != modelsystem.RuntimeRunModeNoAuth {
		credentialSupervisor = orchestrationsvc.NewCredentialDiscoverySupervisorService(
			runtimeCfg,
			localCredentialMgr,
			registrySvc,
			bootstrapCoordinator,
			instance,
			defaultGatewayRegistryTTL,
		)
		credentialSupervisor.MarkRegistered()
	}

	httpHandler := gatewayhttp.NewGatewayHTTPHandler(runtimeCfg, routingPipeline, authControl, nil, nil, nil)

	server := &http.Server{
		Addr:              buildGatewayListenAddr(runtimeCfg),
		Handler:           httpHandler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serveErrCh := make(chan error, 1)
	if credentialSupervisor != nil {
		go credentialSupervisor.Run(ctx)
		log.Printf("stage=credential_supervisor_started service=%s instance=%s", runtimeCfg.ServiceName, instance.ID.String())
	}
	log.Printf("stage=server_start_attempt service=%s transport=http addr=%s", runtimeCfg.ServiceName, server.Addr)
	go func() {
		if serveErr := server.ListenAndServe(); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			serveErrCh <- serveErr
		}
	}()

	log.Printf("stage=server_start_success service=%s transport=http addr=%s", runtimeCfg.ServiceName, server.Addr)

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if shutdownErr := server.Shutdown(shutdownCtx); shutdownErr != nil {
			log.Printf("gateway http server shutdown failed: %v", shutdownErr)
		}
		if unregisterErr := registrySvc.UnRegister(instance); unregisterErr != nil {
			log.Printf("gateway unregister failed: %v", unregisterErr)
		}
		return nil
	case serveErr := <-serveErrCh:
		if unregisterErr := registrySvc.UnRegister(instance); unregisterErr != nil {
			log.Printf("gateway unregister failed after serve error: %v", unregisterErr)
		}
		return serveErr
	}
}

func buildGatewayListenAddr(runtime modelsystem.RuntimeConfig) string {
	return net.JoinHostPort(runtime.HTTPListenHost, strconv.Itoa(runtime.HTTPListenPort))
}

func buildGatewayInstance(runtime modelsystem.RuntimeConfig, activeKeyID string) *commonmodel.ServiceInstance {
	instanceID := parseOrCreateGatewayUUID(runtime.InstanceID)
	serviceID := strings.TrimSpace(runtime.InstanceID)
	if serviceID == "" {
		serviceID = instanceID.String()
	}
	resolvedActiveKeyID := strings.TrimSpace(activeKeyID)
	if resolvedActiveKeyID == "" {
		resolvedActiveKeyID = serviceID
	}

	return &commonmodel.ServiceInstance{
		ID:              instanceID,
		ServiceID:       serviceID,
		Name:            runtime.ServiceName,
		Endpoint:        buildGatewayListenAddr(runtime),
		HeartBeat:       time.Now().UnixMilli(),
		Weight:          1,
		Tags:            []string{"gateway", "http", "startup_phase"},
		ActiveCommKeyID: resolvedActiveKeyID,
		MetaData: map[string]string{
			"run_mode":      string(runtime.RunMode),
			"startup_phase": "bootstrap_to_registry",
		},
	}
}

func parseOrCreateGatewayUUID(raw string) uuid.UUID {
	trimmed := strings.TrimSpace(raw)
	if trimmed != "" {
		if parsed, err := uuid.Parse(trimmed); err == nil {
			return parsed
		}
	}
	return uuid.New()
}

func resolveGatewayEtcdConfig(cfg *modelsystem.ProjectConfig) *modelsystem.EtcdClientConfig {
	if cfg != nil && cfg.Etcd != nil {
		resolved := *cfg.Etcd
		if len(resolved.Endpoints) == 0 {
			resolved.Endpoints = []string{defaultGatewayEtcdAddress}
		}
		if resolved.DialTimeout <= 0 {
			resolved.DialTimeout = 5 * time.Second
		}
		if resolved.OpTimeout <= 0 {
			resolved.OpTimeout = 3 * time.Second
		}
		return &resolved
	}

	return &modelsystem.EtcdClientConfig{
		Endpoints:   []string{defaultGatewayEtcdAddress},
		DialTimeout: 5 * time.Second,
		OpTimeout:   3 * time.Second,
	}
}
