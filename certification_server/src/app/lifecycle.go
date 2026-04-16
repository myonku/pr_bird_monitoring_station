package app

import (
	"context"
	"fmt"
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
	commonsvc "certification_server/src/services/common"
	communicationsvc "certification_server/src/services/communication"
	orchestrationsvc "certification_server/src/services/orchestration"

	"github.com/google/uuid"
	"google.golang.org/grpc"
)

const (
	defaultCertificationConfigPath  = "settings.toml"
	defaultCertificationEtcdAddress = "127.0.0.1:2379"
	defaultCertificationRegistryTTL = int64(30)
)

// Run 启动认证中心最小生命周期：配置 -> 依赖 -> 跳过自身bootstrap -> 注册 -> 最小gRPC运行。
func Run() error {
	cfg, err := modelsystem.LoadConfig(defaultCertificationConfigPath)
	if err != nil {
		return err
	}

	runtimeCfg := cfg.Runtime.Normalized("certification_server")
	log.Printf("stage=config_loaded service=%s run_mode=%s", runtimeCfg.ServiceName, runtimeCfg.RunMode)

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

	etcdCfg := resolveCertificationEtcdConfig(cfg)
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

	keyManager, startupParams, err := commonsvc.NewSecretKeyServiceFromProjectConfig(cfg, nil, mysqlClient)
	if err != nil {
		return err
	}
	sessionManager := commonsvc.NewSessionService(redisClient)
	tokenManager := commonsvc.NewTokenService(mysqlClient, redisClient)
	userCredentialManager := commonsvc.NewUserCredentialService()
	routingPipeline := communicationsvc.NewRoutingPayloadPipelineService()
	trafficStation := communicationsvc.NewTrafficStationService(routingPipeline)
	authOrchestrator := orchestrationsvc.NewAuthRequestOrchestratorServiceWithDeps(
		keyManager,
		sessionManager,
		tokenManager,
		userCredentialManager,
	)
	if runtimeCfg.RunMode != modelsystem.RuntimeRunModeNoAuth &&
		strings.TrimSpace(startupParams.ActiveKeyID) == "" &&
		strings.TrimSpace(runtimeCfg.InstanceID) == "" {
		return fmt.Errorf("bootstrap identity requires active_key_id or instance_id")
	}
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
	communicationsvc.RegisterAuthAuthorityBootstrapRPC(grpcServer, authOrchestrator, trafficStation)
	communicationsvc.RegisterAuthAuthorityRemoteAuthRPC(grpcServer, authOrchestrator, trafficStation)
	communicationsvc.RegisterAuthAuthorityExternalAuthRPC(grpcServer, authOrchestrator, trafficStation)
	communicationsvc.RegisterAuthAuthorityTokenRefreshRPC(grpcServer, authOrchestrator, trafficStation)

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
