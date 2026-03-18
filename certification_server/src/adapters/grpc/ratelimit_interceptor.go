package grpcadapter

import (
	"context"
	"fmt"

	ratelimitif "certification_server/src/interfaces/ratelimit"
	authmodel "certification_server/src/models/auth"
	ratelimituc "certification_server/src/usecase/ratelimit"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// IUnaryRateLimitInputBuilder 定义 unary 请求上下文到限流输入的构建接口。
type IUnaryRateLimitInputBuilder interface {
	Build(ctx context.Context, fullMethod string, req any) (*ratelimitif.InboundRateLimitInput, error)
}

// UnaryRateLimitInterceptor 在认证中心 gRPC 服务端执行入站限流。
type UnaryRateLimitInterceptor struct {
	Usecase *ratelimituc.EnforceInboundUsecase
	Builder IUnaryRateLimitInputBuilder
}

// Intercept 执行 unary 限流检查。
func (i *UnaryRateLimitInterceptor) Intercept(
	ctx context.Context,
	req any,
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (any, error) {
	if i == nil || i.Usecase == nil || i.Builder == nil {
		return handler(ctx, req)
	}
	if info == nil {
		return nil, status.Error(codes.Internal, "grpc method info is nil")
	}

	input, err := i.Builder.Build(ctx, info.FullMethod, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "build ratelimit descriptor failed: %v", err)
	}

	decision, err := i.Usecase.Execute(ctx, &ratelimituc.EnforceInboundRequest{Input: input})
	if err != nil {
		if err == ratelimituc.ErrRateLimited {
			setRateLimitTrailer(ctx, decision)
			msg := "request is rate limited"
			if decision != nil && decision.Reason != "" {
				msg = decision.Reason
			}
			return nil, status.Error(codes.ResourceExhausted, msg)
		}
		return nil, status.Errorf(codes.Internal, "ratelimit evaluate failed: %v", err)
	}

	return handler(ctx, req)
}

func setRateLimitTrailer(ctx context.Context, decision *authmodel.RateLimitDecision) {
	if decision == nil {
		_ = grpc.SetTrailer(ctx, metadata.Pairs("retry-after", "1"))
		return
	}
	_ = grpc.SetTrailer(ctx, metadata.Pairs(
		"retry-after", fmt.Sprintf("%d", decision.RetryAfterSec),
		"ratelimit-rule-id", decision.ViolatedRuleID,
	))
}
