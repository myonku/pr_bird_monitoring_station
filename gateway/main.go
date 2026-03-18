package main

import (
	"context"
	"errors"

	"gateway/src/app"
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
	gatewayApp := &app.GatewayApp{
		Lifecycle: &app.HookLifecycle{},
		HTTP:      &noopHTTPServer{},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := gatewayApp.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		panic(err)
	}
}
