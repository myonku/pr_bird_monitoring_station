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
	communicationif "gateway/src/iface/communication"
	commonmodel "gateway/src/models/common"
	modelsystem "gateway/src/models/system"
	"gateway/src/repo"
	commonsvc "gateway/src/services/common"
	communicationsvc "gateway/src/services/communication"
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
	trafficStation := communicationsvc.NewTrafficStationService(routingPipeline)

	_, startupParams, err := commonsvc.NewSecretKeyServiceFromProjectConfig(cfg, nil, nil)
	if err != nil {
		return err
	}
	log.Printf("stage=dependencies_initialized service=%s", runtimeCfg.ServiceName)

	if runtimeCfg.RunMode == modelsystem.RuntimeRunModeNoAuth {
		log.Printf("stage=bootstrap_skipped_or_ready service=%s mode=no_auth", runtimeCfg.ServiceName)
	} else if err = ensureGatewayBootstrapReady(runtimeCfg, startupParams, localCredentialMgr, trafficStation); err != nil {
		return err
	}

	instance := buildGatewayInstance(runtimeCfg, startupParams.ActiveKeyID)
	log.Printf("stage=registry_register_attempt service=%s instance=%s", instance.Name, instance.ID.String())
	if err = registrySvc.Register(instance, defaultGatewayRegistryTTL); err != nil {
		return err
	}
	log.Printf("stage=registry_register_success service=%s instance=%s endpoint=%s", instance.Name, instance.ID.String(), instance.Endpoint)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	server := &http.Server{
		Addr:              buildGatewayListenAddr(runtimeCfg),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serveErrCh := make(chan error, 1)
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

func ensureGatewayBootstrapReady(
	runtime modelsystem.RuntimeConfig,
	startupParams modelsystem.SecretKeyStartupParams,
	localCredentialMgr commonif.ILocalCredentialManager,
	trafficStation communicationif.ITrafficStation,
) error {
	startupOrchestrator := orchestrationsvc.NewBootstrapStartupOrchestratorService(
		localCredentialMgr,
		trafficStation,
		defaultAuthAuthorityName,
	)
	result, err := startupOrchestrator.EnsureReady(
		context.Background(),
		&orchestrationsvc.BootstrapStartupRequest{
			Runtime:              runtime,
			StartupParams:        startupParams,
			AuthAuthorityService: defaultAuthAuthorityName,
		},
	)
	if err != nil {
		return err
	}

	log.Printf(
		"stage=bootstrap_skipped_or_ready service=%s mode=%s auth_authority=%s authority_endpoint=%s stage=%s credential_key=%s",
		runtime.ServiceName,
		runtime.RunMode,
		defaultAuthAuthorityName,
		result.AuthorityEndpoint,
		result.Stage,
		result.CredentialKey,
	)
	return nil
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

	return &commonmodel.ServiceInstance{
		ID:              instanceID,
		ServiceID:       serviceID,
		Name:            runtime.ServiceName,
		Endpoint:        buildGatewayListenAddr(runtime),
		HeartBeat:       time.Now().UnixMilli(),
		Weight:          1,
		Tags:            []string{"gateway", "http", "startup_phase"},
		ActiveCommKeyID: strings.TrimSpace(activeKeyID),
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
