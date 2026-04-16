package rpcservice_test

import (
	"context"
	"errors"
	"testing"

	modelsystem "certification_server/src/models/system"
	rpcservice "certification_server/src/services/communication/rpc_service"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestMapAuthRPCError(t *testing.T) {
	t.Run("maps auth errors", func(t *testing.T) {
		err := rpcservice.MapAuthRPCError(&modelsystem.ErrTokenNotRefreshType, codes.Internal, "token refresh failed")
		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("expected grpc status error, got %T", err)
		}
		if st.Code() != codes.InvalidArgument {
			t.Fatalf("expected invalid argument, got %s", st.Code())
		}
	})

	t.Run("maps not found auth errors", func(t *testing.T) {
		err := rpcservice.MapAuthRPCError(&modelsystem.ErrUserNotFound, codes.Internal, "user password auth failed")
		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("expected grpc status error, got %T", err)
		}
		if st.Code() != codes.NotFound {
			t.Fatalf("expected not found, got %s", st.Code())
		}
	})

	t.Run("maps context deadline", func(t *testing.T) {
		err := rpcservice.MapAuthRPCError(context.DeadlineExceeded, codes.Internal, "verify token failed")
		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("expected grpc status error, got %T", err)
		}
		if st.Code() != codes.DeadlineExceeded {
			t.Fatalf("expected deadline exceeded, got %s", st.Code())
		}
	})

	t.Run("passes through grpc status", func(t *testing.T) {
		raw := status.Error(codes.PermissionDenied, "already mapped")
		mapped := rpcservice.MapAuthRPCError(raw, codes.Internal, "ignored")
		if !errors.Is(mapped, raw) {
			t.Fatalf("expected grpc status error to pass through")
		}
	})
}
