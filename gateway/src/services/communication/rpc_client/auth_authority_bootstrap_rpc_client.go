package rpcclient

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	authv1 "gateway/src/gen/auth/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
)

// BootstrapHandshakeRequest 表示网关在冷启动阶段向认证中心发起的最小握手请求。
type BootstrapHandshakeRequest struct {
	EntityType string
	EntityID   string
	Audience   string
	KeyID      string
}

// BootstrapHandshakeResult 表示最小握手结果快照。
type BootstrapHandshakeResult struct {
	Stage           string
	ActiveCommKeyID string
}

// BootstrapRPCClient 负责执行认证中心 bootstrap 最小 RPC 调用。
type BootstrapRPCClient struct {
	endpoint    string
	dialTimeout time.Duration
	callTimeout time.Duration
}

func NewBootstrapRPCClient(endpoint string) *BootstrapRPCClient {
	return &BootstrapRPCClient{
		endpoint:    strings.TrimSpace(endpoint),
		dialTimeout: 3 * time.Second,
		callTimeout: 5 * time.Second,
	}
}

func (c *BootstrapRPCClient) ExecuteBootstrapHandshake(
	ctx context.Context,
	req *BootstrapHandshakeRequest,
) (*BootstrapHandshakeResult, error) {
	if req == nil {
		return nil, fmt.Errorf("bootstrap handshake request is nil")
	}
	if c.endpoint == "" {
		return nil, fmt.Errorf("auth authority endpoint is required")
	}
	if strings.TrimSpace(req.EntityType) == "" || strings.TrimSpace(req.EntityID) == "" {
		return nil, fmt.Errorf("bootstrap entity_type and entity_id are required")
	}
	entityType, err := mapEntityType(req.EntityType)
	if err != nil {
		return nil, err
	}
	options := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}
	conn, err := grpc.NewClient(
		c.endpoint,
		options...,
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

	client := authv1.NewAuthAuthorityBootstrapServiceClient(conn)

	challengeReq := &authv1.BootstrapChallengeRequest{
		EntityType: entityType,
		EntityId:   strings.TrimSpace(req.EntityID),
		KeyId:      strings.TrimSpace(req.KeyID),
		Audience:   strings.TrimSpace(req.Audience),
		TtlSec:     60,
	}
	challengeCtx, challengeCancel := context.WithTimeout(ctx, c.callTimeout)
	challengeResp, err := client.InitBootstrapChallenge(challengeCtx, challengeReq)
	challengeCancel()
	if err != nil {
		return nil, fmt.Errorf("bootstrap challenge rpc failed: %w", err)
	}
	challenge := challengeResp.GetChallenge()
	challengeID := strings.TrimSpace(challenge.GetChallengeId())
	challengeKeyID := strings.TrimSpace(challenge.GetKeyId())
	if challengeID == "" {
		return nil, fmt.Errorf("bootstrap challenge response missing challenge_id")
	}
	if challengeKeyID == "" {
		challengeKeyID = strings.TrimSpace(req.KeyID)
	}

	authReq := &authv1.BootstrapAuthenticateRequest{
		Challenge: challenge,
		Signed: &authv1.SignedChallengeResponse{
			ChallengeId:        challengeID,
			KeyId:              challengeKeyID,
			SignatureAlgorithm: authv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519,
			Signature:          base64.StdEncoding.EncodeToString([]byte("bootstrap:" + challengeID)),
			SignedAtMs:         time.Now().UnixMilli(),
		},
		Scopes:                 []string{"service:bootstrap"},
		Role:                   "service",
		RequireDownstreamToken: false,
	}
	authCtx, authCancel := context.WithTimeout(ctx, c.callTimeout)
	authResp, err := client.AuthenticateBootstrap(authCtx, authReq)
	authCancel()
	if err != nil {
		return nil, fmt.Errorf("bootstrap authenticate rpc failed: %w", err)
	}

	stage := normalizeBootstrapStage(authResp.GetStage())
	if stage == "" {
		return nil, fmt.Errorf("bootstrap authenticate response missing stage")
	}

	return &BootstrapHandshakeResult{
		Stage:           stage,
		ActiveCommKeyID: strings.TrimSpace(authResp.GetActiveCommKeyId()),
	}, nil
}

func waitForConnectionReady(ctx context.Context, conn *grpc.ClientConn) error {
	conn.Connect()
	for {
		state := conn.GetState()
		if state == connectivity.Ready {
			return nil
		}
		if !conn.WaitForStateChange(ctx, state) {
			if err := ctx.Err(); err != nil {
				return err
			}
			return fmt.Errorf("connection did not reach ready state")
		}
	}
}

func mapEntityType(raw string) (authv1.EntityType, error) {
	switch strings.TrimSpace(strings.ToLower(raw)) {
	case "user":
		return authv1.EntityType_ENTITY_TYPE_USER, nil
	case "device":
		return authv1.EntityType_ENTITY_TYPE_DEVICE, nil
	case "service":
		return authv1.EntityType_ENTITY_TYPE_SERVICE, nil
	default:
		return authv1.EntityType_ENTITY_TYPE_UNSPECIFIED, fmt.Errorf("unsupported bootstrap entity_type: %q", strings.TrimSpace(raw))
	}
}

func normalizeBootstrapStage(stage authv1.BootstrapStage) string {
	switch stage {
	case authv1.BootstrapStage_BOOTSTRAP_STAGE_READY:
		return "ready"
	case authv1.BootstrapStage_BOOTSTRAP_STAGE_UNINITIALIZED:
		return "uninitialized"
	case authv1.BootstrapStage_BOOTSTRAP_STAGE_CHALLENGING:
		return "challenging"
	case authv1.BootstrapStage_BOOTSTRAP_STAGE_AUTHENTICATING:
		return "authenticating"
	case authv1.BootstrapStage_BOOTSTRAP_STAGE_UNSPECIFIED:
		return ""
	default:
		return strings.TrimSpace(strings.ToLower(stage.String()))
	}
}
