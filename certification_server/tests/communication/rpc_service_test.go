package rpcservice_test

import (
	"context"
	"testing"

	rpcservice "certification_server/src/services/communication/rpc_service"
)

func TestRPCServiceConstructorAliases(t *testing.T) {
	if svc := rpcservice.NewAuthAuthorityBootstrapRPCService(nil, nil); svc == nil {
		t.Fatalf("expected bootstrap rpc constructor to return service")
	}
	if svc := rpcservice.NewAuthAuthorityRemoteAuthRPCService(nil, nil); svc == nil {
		t.Fatalf("expected remote auth rpc constructor to return service")
	}
	if svc := rpcservice.NewAuthAuthorityExternalAuthRPCService(nil, nil); svc == nil {
		t.Fatalf("expected external auth rpc constructor to return service")
	}
	if svc := rpcservice.NewAuthAuthorityTokenRefreshRPCService(nil, nil); svc == nil {
		t.Fatalf("expected token refresh rpc constructor to return service")
	}
	rpcservice.RegisterAuthAuthorityBootstrapRPC(nil, nil, nil)
	rpcservice.RegisterAuthAuthorityRemoteAuthRPC(nil, nil, nil)
	rpcservice.RegisterAuthAuthorityExternalAuthRPC(nil, nil, nil)
	rpcservice.RegisterAuthAuthorityTokenRefreshRPC(nil, nil, nil)
}

func TestRpcServiceExports(t *testing.T) {
	if err := rpcservice.MapAuthRPCError(context.DeadlineExceeded, 0, "fallback"); err == nil {
		t.Fatalf("expected mapped error")
	}
}
