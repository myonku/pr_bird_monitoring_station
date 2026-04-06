package main

import (
	"context"
	"errors"
	"os"

	grpcadapter "certification_server/src/adapters/grpc"
	"certification_server/src/app"
	modelsystem "certification_server/src/models/system"
	commsecsvc "certification_server/src/services/commsec"
)

func main() {
	settingsPath := os.Getenv("CERTIFICATION_SETTINGS_PATH")
	cfg, err := modelsystem.LoadConfig(settingsPath)
	if err != nil {
		panic(err)
	}
	secretKeyParams := cfg.BuildSecretKeyStartupParams("certification_server")

	if _, err = commsecsvc.NewSecretKeyServiceFromStartupParams(secretKeyParams, nil, nil); err != nil {
		panic(err)
	}

	grpcServer, err := grpcadapter.NewServer(grpcadapter.ServerOptions{Address: ":50051"})
	if err != nil {
		panic(err)
	}

	certApp := &app.CertificationApp{
		Lifecycle: &app.HookLifecycle{},
		GRPC:      grpcServer,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = certApp.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		panic(err)
	}
}
