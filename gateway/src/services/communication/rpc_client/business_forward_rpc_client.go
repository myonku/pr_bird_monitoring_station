package rpcclient

import (
	"context"
	"fmt"
	"strings"
	"time"

	businessv1 "gateway/src/gen/business/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	defaultBusinessForwardDialTimeout = 3 * time.Second
	defaultBusinessForwardCallTimeout = 5 * time.Second
	defaultBusinessForwardMaxRecvSize = 16 * 1024 * 1024
	defaultBusinessForwardMaxSendSize = 16 * 1024 * 1024
)

// BusinessForwardRPCClient 负责调用目标服务的统一业务转发 gRPC 入口。
type BusinessForwardRPCClient struct {
	endpoint    string
	dialTimeout time.Duration
	callTimeout time.Duration
}

func NewBusinessForwardRPCClient(endpoint string) *BusinessForwardRPCClient {
	return &BusinessForwardRPCClient{
		endpoint:    strings.TrimSpace(endpoint),
		dialTimeout: defaultBusinessForwardDialTimeout,
		callTimeout: defaultBusinessForwardCallTimeout,
	}
}

func (c *BusinessForwardRPCClient) ForwardBusiness(
	ctx context.Context,
	req *businessv1.BusinessForwardRequest,
) (*businessv1.BusinessForwardResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("business forward request is nil")
	}
	if c.endpoint == "" {
		return nil, fmt.Errorf("target service endpoint is required")
	}
	if strings.TrimSpace(req.GetRouteKey()) == "" {
		return nil, fmt.Errorf("route key is required")
	}

	conn, err := grpc.NewClient(
		c.endpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(defaultBusinessForwardMaxRecvSize),
			grpc.MaxCallSendMsgSize(defaultBusinessForwardMaxSendSize),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("dial target service failed: %w", err)
	}
	defer func() {
		_ = conn.Close()
	}()

	dialCtx, dialCancel := context.WithTimeout(ctx, c.dialTimeout)
	if err := waitForConnectionReady(dialCtx, conn); err != nil {
		dialCancel()
		return nil, fmt.Errorf("wait for target service connection ready failed: %w", err)
	}
	dialCancel()

	client := businessv1.NewBusinessForwardServiceClient(conn)
	callCtx, callCancel := context.WithTimeout(ctx, c.callTimeout)
	resp, err := client.ForwardBusiness(callCtx, req)
	callCancel()
	if err != nil {
		return nil, fmt.Errorf("forward business rpc failed: %w", err)
	}

	return resp, nil
}
