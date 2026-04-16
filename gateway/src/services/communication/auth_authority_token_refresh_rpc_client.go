package communication

import (
	"context"
	"fmt"
	"strings"
	"time"

	authv1 "gateway/src/gen/auth/v1"
	authif "gateway/src/iface/auth"
	authmodel "gateway/src/models/auth"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// TokenRefreshRPCClient 负责调用认证中心 token_refresh proto 服务。
type TokenRefreshRPCClient struct {
	endpoint    string
	dialTimeout time.Duration
	callTimeout time.Duration
}

func NewTokenRefreshRPCClient(endpoint string) *TokenRefreshRPCClient {
	return &TokenRefreshRPCClient{
		endpoint:    strings.TrimSpace(endpoint),
		dialTimeout: 3 * time.Second,
		callTimeout: 5 * time.Second,
	}
}

func (c *TokenRefreshRPCClient) RefreshTokenBundle(
	ctx context.Context,
	req *authif.TokenRefreshRequest,
) (*authmodel.TokenBundle, error) {
	if req == nil {
		return nil, fmt.Errorf("token refresh request is nil")
	}
	if c.endpoint == "" {
		return nil, fmt.Errorf("auth authority endpoint is required")
	}
	if strings.TrimSpace(req.RefreshToken) == "" {
		return nil, fmt.Errorf("refresh token is required")
	}

	conn, err := grpc.NewClient(
		c.endpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("dial auth authority failed: %w", err)
	}
	defer func() {
		_ = conn.Close()
	}()

	dialCtx, dialCancel := context.WithTimeout(ctx, c.dialTimeout)
	if err := waitForConnectionReady(dialCtx, conn); err != nil {
		dialCancel()
		return nil, fmt.Errorf("wait for auth authority connection ready failed: %w", err)
	}
	dialCancel()

	client := authv1.NewAuthAuthorityTokenRefreshServiceClient(conn)
	callCtx, callCancel := context.WithTimeout(ctx, c.callTimeout)
	resp, err := client.RefreshTokenBundle(
		callCtx,
		&authv1.TokenRefreshRequest{
			RefreshToken: strings.TrimSpace(req.RefreshToken),
			ClientId:     strings.TrimSpace(req.ClientID),
			GatewayId:    strings.TrimSpace(req.GatewayID),
			SourceIp:     strings.TrimSpace(req.SourceIP),
			UserAgent:    strings.TrimSpace(req.UserAgent),
			RequestId:    strings.TrimSpace(req.RequestID),
			TraceId:      strings.TrimSpace(req.TraceID),
		},
	)
	callCancel()
	if err != nil {
		return nil, fmt.Errorf("refresh token bundle rpc failed: %w", err)
	}

	return &authmodel.TokenBundle{
		AccessToken:     mapProtoIssuedTokenToGatewayModel(resp.GetAccessToken()),
		RefreshToken:    mapProtoIssuedTokenToGatewayModel(resp.GetRefreshToken()),
		DownstreamToken: mapProtoIssuedTokenToGatewayModel(resp.GetDownstreamToken()),
	}, nil
}
