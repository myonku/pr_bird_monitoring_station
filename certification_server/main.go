package main

import (
	"context"
	"errors"

	grpcadapter "certification_server/src/adapters/grpc"
	"certification_server/src/app"
)

func main() {
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
