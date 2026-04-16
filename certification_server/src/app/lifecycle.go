package app

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	commonmodel "certification_server/src/models/common"
	modelsystem "certification_server/src/models/system"
	"certification_server/src/repo"
	authcontrolsvc "certification_server/src/services/authcontrol"
	commonsvc "certification_server/src/services/common"
	communicationsvc "certification_server/src/services/communication"
	rpcservice "certification_server/src/services/communication/rpc_service"
	orchestrationsvc "certification_server/src/services/orchestration"

	"github.com/google/uuid"
	"google.golang.org/grpc"
)

const (
	defaultCertificationConfigPath  = "settings.toml"
	defaultCertificationEtcdAddress = "127.0.0.1:2379"
	defaultCertificationRegistryTTL = int64(30)
)

// Run 启动认证中心最小生命周期：配置 -> no-auth 保护 -> 依赖 -> 跳过自身bootstrap -> 注册 -> 最小gRPC运行。
func Run() error {
	cfg, err := modelsystem.LoadConfig(defaultCertificationConfigPath)
	if err != nil {
		return err
	}

	normalizedCfg := cfg.Normalized("certification_server")
	runtimeCfg := *normalizedCfg.Runtime
	log.Printf("stage=config_loaded service=%s run_mode=%s", runtimeCfg.ServiceName, runtimeCfg.RunMode)
	if runtimeCfg.RunMode == modelsystem.RuntimeRunModeNoAuth {
		log.Printf("stage=no_auth_self_stop service=%s reason=run_mode_no_auth", runtimeCfg.ServiceName)
		return nil
	}

	var mysqlClient *repo.MySQLClient
	if cfg.MySQL != nil {
		mysqlClient, err = repo.NewMySQLClient(cfg.MySQL)
		if err != nil {
			return err
		}
		defer func() {
			if closeErr := mysqlClient.Close(); closeErr != nil {
				log.Printf("certification mysql close failed: %v", closeErr)
			}
		}()
	}

	var redisClient *repo.RedisClient
	if cfg.Redis != nil {
		redisClient, err = repo.NewRedisClient(cfg.Redis)
		if err != nil {
			return err
		}
		defer func() {
			if closeErr := redisClient.Close(); closeErr != nil {
				log.Printf("certification redis close failed: %v", closeErr)
			}
		}()
	}

	etcdCfg := resolveCertificationEtcdConfig(&normalizedCfg)
	etcdClient, err := repo.NewEtcdClient(etcdCfg)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := etcdClient.Close(); closeErr != nil {
			log.Printf("certification etcd close failed: %v", closeErr)
		}
	}()

	registrySvc := commonsvc.NewRegistryService(etcdClient, "", 0)

	keyManager, startupParams, err := commonsvc.NewSecretKeyServiceFromProjectConfig(&normalizedCfg, nil, mysqlClient)
	if err != nil {
		return err
	}
	authControl := authcontrolsvc.NewInboundAuthControlService(*normalizedCfg.AuthControl)
	sessionManager := commonsvc.NewSessionService(redisClient)
	tokenManager := commonsvc.NewTokenService(mysqlClient, redisClient)
	userCredentialManager := commonsvc.NewUserCredentialService(mysqlClient)
	routingPipeline := communicationsvc.NewRoutingPayloadPipelineService()
	trafficStation := communicationsvc.NewTrafficStationService(routingPipeline, authControl)
	authOrchestrator := orchestrationsvc.NewAuthRequestOrchestratorServiceWithDeps(
		keyManager,
		sessionManager,
		tokenManager,
		userCredentialManager,
	)
	log.Printf("stage=dependencies_initialized service=%s", runtimeCfg.ServiceName)

	log.Printf("stage=bootstrap_skipped_or_ready service=%s mode=%s reason=authority_self_bootstrap_disabled", runtimeCfg.ServiceName, runtimeCfg.RunMode)

	instance := buildCertificationInstance(runtimeCfg, startupParams.ActiveKeyID)
	log.Printf("stage=registry_register_attempt service=%s instance=%s", instance.Name, instance.ID.String())
	if err = registrySvc.Register(instance, defaultCertificationRegistryTTL); err != nil {
		return err
	}
	log.Printf("stage=registry_register_success service=%s instance=%s endpoint=%s", instance.Name, instance.ID.String(), instance.Endpoint)

	log.Printf("stage=server_start_attempt service=%s transport=grpc addr=%s", runtimeCfg.ServiceName, buildCertificationListenAddr(runtimeCfg))
	listener, err := net.Listen("tcp", buildCertificationListenAddr(runtimeCfg))
	if err != nil {
		_ = registrySvc.UnRegister(instance)
		return err
	}

	grpcServer := grpc.NewServer()
	rpcservice.RegisterAuthAuthorityBootstrapRPC(grpcServer, authOrchestrator, trafficStation)
	rpcservice.RegisterAuthAuthorityRemoteAuthRPC(grpcServer, authOrchestrator, trafficStation)
	rpcservice.RegisterAuthAuthorityExternalAuthRPC(grpcServer, authOrchestrator, trafficStation)
	rpcservice.RegisterAuthAuthorityTokenRefreshRPC(grpcServer, authOrchestrator, trafficStation)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serveErrCh := make(chan error, 1)
	go func() {
		if serveErr := grpcServer.Serve(listener); serveErr != nil {
			serveErrCh <- serveErr
		}
	}()

	log.Printf("stage=server_start_success service=%s transport=grpc addr=%s", runtimeCfg.ServiceName, listener.Addr().String())

	select {
	case <-ctx.Done():
		grpcServer.GracefulStop()
		if unregisterErr := registrySvc.UnRegister(instance); unregisterErr != nil {
			log.Printf("certification unregister failed: %v", unregisterErr)
		}
		return nil
	case serveErr := <-serveErrCh:
		grpcServer.Stop()
		if unregisterErr := registrySvc.UnRegister(instance); unregisterErr != nil {
			log.Printf("certification unregister failed after serve error: %v", unregisterErr)
		}
		return serveErr
	}
}

func buildCertificationListenAddr(runtime modelsystem.RuntimeConfig) string {
	return net.JoinHostPort(runtime.GRPCListenHost, strconv.Itoa(runtime.GRPCListenPort))
}

// buildCertificationInstance 使用启动阶段解析出的有效公钥引用ID；active_key_id 缺失时已在启动参数中回退到 instance_id。
func buildCertificationInstance(runtime modelsystem.RuntimeConfig, activeKeyID string) *commonmodel.ServiceInstance {
	instanceID := parseOrCreateCertificationUUID(runtime.InstanceID)
	serviceID := strings.TrimSpace(runtime.InstanceID)
	if serviceID == "" {
		serviceID = instanceID.String()
	}

	return &commonmodel.ServiceInstance{
		ID:              instanceID,
		ServiceID:       serviceID,
		Name:            runtime.ServiceName,
		Endpoint:        buildCertificationListenAddr(runtime),
		HeartBeat:       time.Now().UnixMilli(),
		Weight:          1,
		Tags:            []string{"certification_server", "grpc", "startup_phase"},
		ActiveCommKeyID: strings.TrimSpace(activeKeyID),
		MetaData: map[string]string{
			"run_mode":      string(runtime.RunMode),
			"startup_phase": "bootstrap_to_registry",
		},
	}
}

func parseOrCreateCertificationUUID(raw string) uuid.UUID {
	trimmed := strings.TrimSpace(raw)
	if trimmed != "" {
		if parsed, err := uuid.Parse(trimmed); err == nil {
			return parsed
		}
	}
	return uuid.New()
}

func resolveCertificationEtcdConfig(cfg *modelsystem.ProjectConfig) *modelsystem.EtcdClientConfig {
	if cfg != nil && cfg.Etcd != nil {
		resolved := *cfg.Etcd
		if len(resolved.Endpoints) == 0 {
			resolved.Endpoints = []string{defaultCertificationEtcdAddress}
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
		Endpoints:   []string{defaultCertificationEtcdAddress},
		DialTimeout: 5 * time.Second,
		OpTimeout:   3 * time.Second,
	}
}
