package rpcclient

import (
	"context"
	"fmt"
	"strings"
	"time"

	authv1 "gateway/src/gen/auth/v1"
	authmodel "gateway/src/models/auth"

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
	Signer     authmodel.ChallengeSigner
}

// BootstrapHandshakeResult 表示最小握手结果快照。
type BootstrapHandshakeResult struct {
	Stage           string
	Identity        *authmodel.IdentityContext
	Session         *authmodel.Session
	Tokens          authmodel.TokenBundle
	ActiveCommKeyID string
	IssuedAt        time.Time
	ExpiresAt       time.Time
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
	if req.Signer == nil {
		return nil, fmt.Errorf("challenge signer is required")
	}

	challengePayload, err := mapProtoChallengePayloadToModel(challenge)
	if err != nil {
		return nil, fmt.Errorf("map bootstrap challenge payload failed: %w", err)
	}
	signerCtx, signerCancel := context.WithTimeout(ctx, c.callTimeout)
	signedChallenge, err := req.Signer(signerCtx, challengePayload)
	signerCancel()
	if err != nil {
		return nil, fmt.Errorf("bootstrap challenge signing failed: %w", err)
	}
	if signedChallenge == nil {
		return nil, fmt.Errorf("bootstrap challenge signer returned nil response")
	}
	signedAlgorithm, err := mapGatewaySignatureAlgorithmToProto(signedChallenge.SignatureAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("map bootstrap signature algorithm failed: %w", err)
	}
	signedChallengeID := strings.TrimSpace(signedChallenge.ChallengeID.String())
	if signedChallengeID == "" || signedChallengeID == "00000000-0000-0000-0000-000000000000" {
		signedChallengeID = challengeID
	}
	signedKeyID := strings.TrimSpace(signedChallenge.KeyID)
	if signedKeyID == "" {
		signedKeyID = challengeKeyID
	}

	authReq := &authv1.BootstrapAuthenticateRequest{
		Challenge: challenge,
		Signed: &authv1.SignedChallengeResponse{
			ChallengeId:        signedChallengeID,
			KeyId:              signedKeyID,
			SignatureAlgorithm: signedAlgorithm,
			Signature:          strings.TrimSpace(signedChallenge.Signature),
			SignedAtMs:         signedChallenge.SignedAt.UTC().UnixMilli(),
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
		Identity:        mapProtoIdentityToGatewayModel(authResp.GetIdentity()),
		Session:         mapProtoSessionToModel(authResp.GetSession()),
		Tokens:          mapProtoTokenBundleToGatewayModel(authResp.GetTokens()),
		ActiveCommKeyID: strings.TrimSpace(authResp.GetActiveCommKeyId()),
		IssuedAt:        fromUnixMillis(authResp.GetIssuedAtMs()),
		ExpiresAt:       fromUnixMillis(authResp.GetExpiresAtMs()),
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

func mapProtoChallengePayloadToModel(payload *authv1.ChallengePayload) (*authmodel.ChallengePayload, error) {
	if payload == nil {
		return nil, fmt.Errorf("bootstrap challenge payload is nil")
	}
	entityType := mapProtoEntityTypeToModel(payload.GetEntityType())
	return &authmodel.ChallengePayload{
		ChallengeID: parseUUIDOrNil(payload.GetChallengeId()),
		Issuer:      strings.TrimSpace(payload.GetIssuer()),
		Audience:    strings.TrimSpace(payload.GetAudience()),
		EntityType:  authmodel.EntityType(entityType),
		EntityID:    strings.TrimSpace(payload.GetEntityId()),
		KeyID:       strings.TrimSpace(payload.GetKeyId()),
		Nonce:       strings.TrimSpace(payload.GetNonce()),
		IssuedAt:    fromUnixMillis(payload.GetIssuedAtMs()),
		ExpiresAt:   fromUnixMillis(payload.GetExpiresAtMs()),
	}, nil
}

func mapProtoTokenBundleToGatewayModel(bundle *authv1.TokenBundle) authmodel.TokenBundle {
	if bundle == nil {
		return authmodel.TokenBundle{}
	}
	return authmodel.TokenBundle{
		AccessToken:     mapProtoIssuedTokenToGatewayModel(bundle.GetAccessToken()),
		RefreshToken:    mapProtoIssuedTokenToGatewayModel(bundle.GetRefreshToken()),
		DownstreamToken: mapProtoIssuedTokenToGatewayModel(bundle.GetDownstreamToken()),
	}
}
