package outbound

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	commif "gateway/src/interfaces/communication"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// IGRPCConnProvider 定义按 endpoint 获取 gRPC 连接的抽象。
type IGRPCConnProvider interface {
	GetConn(ctx context.Context, endpoint string) (grpc.ClientConnInterface, error)
}

// IGRPCPayloadCodec 负责将转发请求/响应与 gRPC invoke 入参/回参做编解码。
// 说明: 最小适配器不绑定具体 proto，具体类型由 codec 决定。
type IGRPCPayloadCodec interface {
	BuildRequest(req *commif.OutboundForwardRequest, security *commif.OutboundSecurityContext) (any, error)
	BuildResponse(resp any, headers map[string]string) (*commif.OutboundForwardResponse, error)
	NewResponseContainer() any
}

// GRPCOutboundForwarder 是最小可用的 gRPC 出站转发适配器。
// 边界: 仅负责调用，不负责编排 auth/bootstrap/handshake。
type GRPCOutboundForwarder struct {
	ConnProvider IGRPCConnProvider
	Codec        IGRPCPayloadCodec
}

// Forward 使用 gRPC 客户端调用内部服务。
func (f *GRPCOutboundForwarder) Forward(
	ctx context.Context,
	req *commif.OutboundForwardRequest,
	security *commif.OutboundSecurityContext,
) (*commif.OutboundForwardResponse, error) {
	if f == nil || f.ConnProvider == nil || f.Codec == nil {
		return nil, errors.New("grpc outbound dependencies are required")
	}
	if req == nil {
		return nil, errors.New("forward request is nil")
	}
	if req.Endpoint == "" {
		return nil, errors.New("endpoint is required")
	}

	fullMethod := req.RPCMethod
	if fullMethod == "" {
		fullMethod = req.Method
	}
	if fullMethod == "" {
		return nil, errors.New("grpc method is required")
	}

	conn, err := f.ConnProvider.GetConn(ctx, req.Endpoint)
	if err != nil {
		return nil, err
	}

	invokeReq, err := f.Codec.BuildRequest(req, security)
	if err != nil {
		return nil, err
	}
	invokeResp := f.Codec.NewResponseContainer()

	callCtx := attachSecurityMetadata(ctx, req, security)
	if req.TimeoutMS > 0 {
		var cancel context.CancelFunc
		callCtx, cancel = context.WithTimeout(callCtx, time.Duration(req.TimeoutMS)*time.Millisecond)
		defer cancel()
	}

	header := metadata.MD{}
	if err = conn.Invoke(callCtx, fullMethod, invokeReq, invokeResp, grpc.Header(&header)); err != nil {
		return nil, fmt.Errorf("grpc invoke failed: %w", err)
	}

	return f.Codec.BuildResponse(invokeResp, flattenMetadata(header))
}

func attachSecurityMetadata(
	ctx context.Context,
	req *commif.OutboundForwardRequest,
	security *commif.OutboundSecurityContext,
) context.Context {
	md := metadata.New(map[string]string{})
	for k, v := range req.Headers {
		if k == "" {
			continue
		}
		md.Set(k, v)
	}

	if security != nil && security.Grant != nil {
		md.Set("x-downstream-token-id", security.Grant.TokenID.String())
		md.Set("x-downstream-session-id", security.Grant.SessionID.String())
		md.Set("x-downstream-principal", security.Grant.PrincipalID)
	}
	if security != nil && security.Channel != nil {
		md.Set("x-secure-channel-id", security.Channel.ID.String())
		md.Set("x-secure-channel-suite", string(security.Channel.CipherSuite))
	}
	if security != nil && security.EncryptedMeta != nil {
		md.Set("x-encrypted-seq", strconv.FormatUint(security.EncryptedMeta.Sequence, 10))
		md.Set("x-encrypted-nonce", security.EncryptedMeta.Nonce)
	}

	return metadata.NewOutgoingContext(ctx, md)
}

func flattenMetadata(md metadata.MD) map[string]string {
	res := make(map[string]string, len(md))
	for k, values := range md {
		if len(values) == 0 {
			continue
		}
		res[k] = values[len(values)-1]
	}
	return res
}
