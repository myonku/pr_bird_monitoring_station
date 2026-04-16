package rpcservice

import (
	"context"
	"errors"
	"strings"

	modelsystem "certification_server/src/models/system"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// MapAuthRPCError 将领域错误统一转换为稳定的 gRPC 状态码。
func MapAuthRPCError(err error, fallbackCode codes.Code, fallbackMessage string) error {
	if err == nil {
		return nil
	}

	if _, ok := status.FromError(err); ok {
		return err
	}
	if errors.Is(err, context.Canceled) {
		return status.Error(codes.Canceled, err.Error())
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return status.Error(codes.DeadlineExceeded, err.Error())
	}

	var sysErr *modelsystem.Error
	if errors.As(err, &sysErr) {
		return status.Error(mapSystemErrorCode(sysErr), sysErr.Error())
	}

	if fallbackMessage != "" {
		return status.Errorf(fallbackCode, "%s: %v", fallbackMessage, err)
	}
	return status.Error(fallbackCode, err.Error())
}

func mapSystemErrorCode(sysErr *modelsystem.Error) codes.Code {
	if sysErr == nil {
		return codes.Internal
	}

	info := strings.ToLower(strings.TrimSpace(sysErr.Info))
	switch sysErr.ErrType {
	case modelsystem.AuthErr:
		switch {
		case strings.Contains(info, "not found"):
			return codes.NotFound
		case strings.Contains(info, "not refresh type"):
			return codes.InvalidArgument
		case strings.Contains(info, "required"), strings.Contains(info, "nil"):
			return codes.InvalidArgument
		case strings.Contains(info, "not ready"), strings.Contains(info, "not configured"):
			return codes.FailedPrecondition
		case strings.Contains(info, "disabled"),
			strings.Contains(info, "banned"),
			strings.Contains(info, "rejected"),
			strings.Contains(info, "expired"),
			strings.Contains(info, "not active"),
			strings.Contains(info, "mismatch"):
			return codes.PermissionDenied
		default:
			return codes.PermissionDenied
		}
	case modelsystem.CommSecErr:
		switch {
		case strings.Contains(info, "not found"):
			return codes.NotFound
		case strings.Contains(info, "required"), strings.Contains(info, "nil"), strings.Contains(info, "invalid"), strings.Contains(info, "unsupported"):
			return codes.InvalidArgument
		case strings.Contains(info, "not configured"):
			return codes.FailedPrecondition
		default:
			return codes.Internal
		}
	case modelsystem.RateLimitErr:
		if strings.Contains(info, "rate limited") {
			return codes.ResourceExhausted
		}
		if strings.Contains(info, "required") || strings.Contains(info, "nil") || strings.Contains(info, "invalid") {
			return codes.InvalidArgument
		}
		return codes.Internal
	case modelsystem.GRPCErr:
		if strings.Contains(info, "required") || strings.Contains(info, "nil") || strings.Contains(info, "not ready") {
			return codes.FailedPrecondition
		}
		return codes.Internal
	case modelsystem.AdapterErr, modelsystem.RegistryErr, modelsystem.EtcdErr, modelsystem.RedisErr, modelsystem.MySQLErr, modelsystem.CircuitErr:
		if strings.Contains(info, "required") || strings.Contains(info, "nil") {
			return codes.FailedPrecondition
		}
		return codes.Internal
	case modelsystem.CryptoErr:
		if strings.Contains(info, "invalid") || strings.Contains(info, "unsupported") || strings.Contains(info, "required") {
			return codes.InvalidArgument
		}
		return codes.Internal
	default:
		return codes.Internal
	}
}
