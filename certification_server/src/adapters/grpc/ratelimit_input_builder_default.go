package grpcadapter

import (
	"context"
	"strings"

	ratelimitif "certification_server/src/interfaces/ratelimit"
	authmodel "certification_server/src/models/auth"

	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// DefaultUnaryRateLimitInputBuilder 是认证中心 gRPC 默认限流输入构建器。
type DefaultUnaryRateLimitInputBuilder struct{}

// Build 把 unary 请求上下文映射为限流输入。
func (b *DefaultUnaryRateLimitInputBuilder) Build(
	ctx context.Context,
	fullMethod string,
	req any,
) (*ratelimitif.InboundRateLimitInput, error) {
	input := &ratelimitif.InboundRateLimitInput{
		Scope:     decideScopeByMethod(fullMethod),
		Transport: "grpc",
		Module:    "certification_server",
		Action:    "grpc_unary",
		Route:     fullMethod,
		Method:    fullMethod,
		Headers:   map[string]string{},
		Tags:      map[string]string{},
	}

	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		input.SourceIP = p.Addr.String()
	}

	if md, ok := metadata.FromIncomingContext(ctx); ok {
		copyMD(md, input.Headers)
		input.ClientID = first(md.Get("x-client-id"))
		input.GatewayID = first(md.Get("x-gateway-id"))
		input.SourceService = first(md.Get("x-source-service"))
		input.TargetService = first(md.Get("x-target-service"))
		if sourceIP := first(md.Get("x-source-ip")); sourceIP != "" {
			input.SourceIP = sourceIP
		}
	}

	return input, nil
}

func decideScopeByMethod(fullMethod string) authmodel.RateLimitScope {
	lower := strings.ToLower(fullMethod)
	if strings.Contains(lower, "bootstrap") || strings.Contains(lower, "token") || strings.Contains(lower, "session") {
		return authmodel.RateLimitScopeAuth
	}
	return authmodel.RateLimitScopeInternalRPC
}

func copyMD(md metadata.MD, out map[string]string) {
	for k, values := range md {
		if len(values) == 0 {
			continue
		}
		out[k] = values[len(values)-1]
	}
}

func first(items []string) string {
	if len(items) == 0 {
		return ""
	}
	return items[0]
}
