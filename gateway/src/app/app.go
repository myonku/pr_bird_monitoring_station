package app

import (
	"context"

	modelsystem "gateway/src/models/system"
)

// Lifecycle 定义网关通用行为生命周期。
type Lifecycle interface {
	Boot(ctx context.Context) error
	Shutdown(ctx context.Context) error
}

// HTTPServerPort 定义网关唯一入站服务端口。
type HTTPServerPort interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

// GatewayApp 负责顶层生命周期管理。
type GatewayApp struct {
	Lifecycle Lifecycle
	HTTP      HTTPServerPort
}

// Run 启动网关应用。
func (a *GatewayApp) Run(ctx context.Context) error {
	if a == nil || a.Lifecycle == nil || a.HTTP == nil {
		return &modelsystem.ErrGatewayAppDependenciesRequired
	}

	if err := a.Lifecycle.Boot(ctx); err != nil {
		return err
	}
	return a.HTTP.Start(ctx)
}

// Stop 关闭网关应用。
func (a *GatewayApp) Stop(ctx context.Context) error {
	if a == nil || a.Lifecycle == nil || a.HTTP == nil {
		return &modelsystem.ErrGatewayAppDependenciesRequired
	}
	if err := a.HTTP.Stop(ctx); err != nil {
		return err
	}
	return a.Lifecycle.Shutdown(ctx)
}
