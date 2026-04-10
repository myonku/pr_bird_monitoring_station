package authcontrol

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	bootstrapInitMethodPath = "/bms.auth.v1.AuthAuthorityBootstrapService/InitBootstrapChallenge"
	bootstrapAuthMethodPath = "/bms.auth.v1.AuthAuthorityBootstrapService/AuthenticateBootstrap"
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

	dialCtx, dialCancel := context.WithTimeout(ctx, c.dialTimeout)
	defer dialCancel()
	conn, err := grpc.DialContext(
		dialCtx,
		c.endpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, fmt.Errorf("dial auth authority failed: %w", err)
	}
	defer func() {
		_ = conn.Close()
	}()

	challengeReq, err := structpb.NewStruct(map[string]any{
		"entity_type": req.EntityType,
		"entity_id":   req.EntityID,
		"key_id":      strings.TrimSpace(req.KeyID),
		"audience":    strings.TrimSpace(req.Audience),
		"ttl_sec":     float64(60),
	})
	if err != nil {
		return nil, fmt.Errorf("build bootstrap challenge request failed: %w", err)
	}

	challengeResp := &structpb.Struct{}
	challengeCtx, challengeCancel := context.WithTimeout(ctx, c.callTimeout)
	err = conn.Invoke(challengeCtx, bootstrapInitMethodPath, challengeReq, challengeResp)
	challengeCancel()
	if err != nil {
		return nil, fmt.Errorf("bootstrap challenge rpc failed: %w", err)
	}

	challengeEnvelope := challengeResp.AsMap()
	challengeMap := readMap(challengeEnvelope, "challenge")
	if len(challengeMap) == 0 {
		challengeMap = challengeEnvelope
	}
	challengeID := readString(challengeMap, "challenge_id")
	challengeKeyID := readString(challengeMap, "key_id")
	if challengeID == "" {
		return nil, fmt.Errorf("bootstrap challenge response missing challenge_id")
	}
	if challengeKeyID == "" {
		challengeKeyID = strings.TrimSpace(req.KeyID)
	}

	authReq, err := structpb.NewStruct(map[string]any{
		"challenge": challengeMap,
		"signed": map[string]any{
			"challenge_id":        challengeID,
			"key_id":              challengeKeyID,
			"signature_algorithm": "ed25519",
			"signature":           base64.StdEncoding.EncodeToString([]byte("bootstrap:" + challengeID)),
			"signed_at_ms":        float64(time.Now().UnixMilli()),
		},
		"scopes":                   []any{"service:bootstrap"},
		"role":                     "service",
		"require_downstream_token": false,
	})
	if err != nil {
		return nil, fmt.Errorf("build bootstrap authenticate request failed: %w", err)
	}

	authResp := &structpb.Struct{}
	authCtx, authCancel := context.WithTimeout(ctx, c.callTimeout)
	err = conn.Invoke(authCtx, bootstrapAuthMethodPath, authReq, authResp)
	authCancel()
	if err != nil {
		return nil, fmt.Errorf("bootstrap authenticate rpc failed: %w", err)
	}

	authMap := authResp.AsMap()
	stage := normalizeBootstrapStage(readString(authMap, "stage"))
	if stage == "" {
		return nil, fmt.Errorf("bootstrap authenticate response missing stage")
	}

	return &BootstrapHandshakeResult{
		Stage:           stage,
		ActiveCommKeyID: readString(authMap, "active_comm_key_id"),
	}, nil
}

func readString(m map[string]any, key string) string {
	if len(m) == 0 {
		return ""
	}
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

func readMap(m map[string]any, key string) map[string]any {
	if len(m) == 0 {
		return nil
	}
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	child, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	return child
}

func normalizeBootstrapStage(raw string) string {
	stage := strings.TrimSpace(strings.ToLower(raw))
	switch stage {
	case "ready", "bootstrap_stage_ready", "4":
		return "ready"
	case "uninitialized", "bootstrap_stage_uninitialized", "1":
		return "uninitialized"
	case "challenging", "bootstrap_stage_challenging", "2":
		return "challenging"
	case "authenticating", "bootstrap_stage_authenticating", "3":
		return "authenticating"
	default:
		return stage
	}
}
