package app

import (
	"context"

	modelsystem "certification_server/src/models/system"
)

// Lifecycle 定义认证中心通用行为生命周期。
type Lifecycle interface {
	Boot(ctx context.Context) error
	Shutdown(ctx context.Context) error
}

// GRPCServerPort 定义认证中心唯一入站端口。
type GRPCServerPort interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

// CertificationApp 负责顶层生命周期管理。
type CertificationApp struct {
	Lifecycle Lifecycle
	GRPC      GRPCServerPort
}

// Run 启动认证中心应用。
func (a *CertificationApp) Run(ctx context.Context) error {
	if a == nil || a.Lifecycle == nil || a.GRPC == nil {
		return &modelsystem.ErrAppDependenciesRequired
	}

	if err := a.Lifecycle.Boot(ctx); err != nil {
		return err
	}
	return a.GRPC.Start(ctx)
}

// Stop 关闭认证中心应用。
func (a *CertificationApp) Stop(ctx context.Context) error {
	if a == nil || a.Lifecycle == nil || a.GRPC == nil {
		return &modelsystem.ErrAppDependenciesRequired
	}
	if err := a.GRPC.Stop(ctx); err != nil {
		return err
	}
	return a.Lifecycle.Shutdown(ctx)
}
