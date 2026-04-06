package main

import (
	"context"
	"errors"
	"os"

	outbound "gateway/src/adapters/outbound"
	"gateway/src/app"
	modelsystem "gateway/src/models/system"
	commsecsvc "gateway/src/services/commsec"
)

type noopHTTPServer struct{}

func (s *noopHTTPServer) Start(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func (s *noopHTTPServer) Stop(ctx context.Context) error {
	return nil
}

func main() {
	settingsPath := os.Getenv("GATEWAY_SETTINGS_PATH")
	cfg, err := modelsystem.LoadConfig(settingsPath)
	if err != nil {
		panic(err)
	}
	secretKeyParams := cfg.BuildSecretKeyStartupParams("gateway")

	secretKeySvc, err := commsecsvc.NewSecretKeyServiceFromStartupParams(secretKeyParams, nil, nil)
	if err != nil {
		panic(err)
	}

	forwarder := &outbound.GRPCOutboundForwarder{}
	if err = app.WireInternalAssertion(forwarder, secretKeySvc, cfg); err != nil {
		panic(err)
	}

	gatewayApp := &app.GatewayApp{
		Lifecycle: &app.HookLifecycle{},
		HTTP:      &noopHTTPServer{},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = gatewayApp.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		panic(err)
	}
}
