package communication

import (
	"context"
	"fmt"
	"strings"
	"time"

	authv1 "gateway/src/gen/auth/v1"
	communicationif "gateway/src/iface/communication"
	authmodel "gateway/src/models/auth"
	commonmodel "gateway/src/models/common"
	commsecmodel "gateway/src/models/commsec"

	"github.com/google/uuid"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// ExternalAuthRPCClient 负责调用认证中心 external_auth proto 服务。
type ExternalAuthRPCClient struct {
	endpoint    string
	dialTimeout time.Duration
	callTimeout time.Duration
}

func NewExternalAuthRPCClient(endpoint string) *ExternalAuthRPCClient {
	return &ExternalAuthRPCClient{
		endpoint:    strings.TrimSpace(endpoint),
		dialTimeout: 3 * time.Second,
		callTimeout: 5 * time.Second,
	}
}

func (c *ExternalAuthRPCClient) AuthenticateUserPassword(
	ctx context.Context,
	req *communicationif.UserPasswordAuthRequest,
) (*communicationif.UserPasswordAuthResult, error) {
	if req == nil {
		return nil, fmt.Errorf("user password auth request is nil")
	}
	if c.endpoint == "" {
		return nil, fmt.Errorf("auth authority endpoint is required")
	}
	if strings.TrimSpace(req.Username) == "" {
		return nil, fmt.Errorf("username is required")
	}
	if strings.TrimSpace(req.Password) == "" {
		return nil, fmt.Errorf("password is required")
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

	client := authv1.NewAuthAuthorityExternalAuthServiceClient(conn)
	callCtx, callCancel := context.WithTimeout(ctx, c.callTimeout)
	resp, err := client.ForwardUserPassword(
		callCtx,
		&authv1.UserPasswordAuthRequest{
			Username:  strings.TrimSpace(req.Username),
			Password:  req.Password,
			Audience:  strings.TrimSpace(req.Audience),
			Scopes:    append([]string(nil), req.Scopes...),
			ClientId:  strings.TrimSpace(req.ClientID),
			GatewayId: strings.TrimSpace(req.GatewayID),
			SourceIp:  strings.TrimSpace(req.SourceIP),
			UserAgent: strings.TrimSpace(req.UserAgent),
			RequestId: strings.TrimSpace(req.RequestID),
			TraceId:   strings.TrimSpace(req.TraceID),
		},
	)
	callCancel()
	if err != nil {
		return nil, fmt.Errorf("forward user password rpc failed: %w", err)
	}

	result := &communicationif.UserPasswordAuthResult{
		Identity:  mapProtoIdentityToGatewayModel(resp.GetIdentity()),
		Session:   mapProtoSessionToModel(resp.GetSession()),
		IssuedAt:  fromUnixMillis(resp.GetIssuedAtMs()),
		ExpiresAt: fromUnixMillis(resp.GetExpiresAtMs()),
	}
	if tokens := resp.GetTokens(); tokens != nil {
		result.Tokens = authmodel.TokenBundle{
			AccessToken:     mapProtoIssuedTokenToGatewayModel(tokens.GetAccessToken()),
			RefreshToken:    mapProtoIssuedTokenToGatewayModel(tokens.GetRefreshToken()),
			DownstreamToken: mapProtoIssuedTokenToGatewayModel(tokens.GetDownstreamToken()),
		}
	}

	return result, nil
}

func (c *ExternalAuthRPCClient) ForwardBootstrapChallenge(
	ctx context.Context,
	req *authmodel.ChallengeRequest,
) (*authmodel.ChallengePayload, error) {
	if req == nil {
		return nil, fmt.Errorf("bootstrap challenge request is nil")
	}
	if c.endpoint == "" {
		return nil, fmt.Errorf("auth authority endpoint is required")
	}
	if strings.TrimSpace(req.EntityID) == "" {
		return nil, fmt.Errorf("entity_id is required")
	}

	entityType, err := mapEntityType(string(req.EntityType))
	if err != nil {
		return nil, err
	}

	ttlSec := req.TTLSec
	if ttlSec <= 0 {
		ttlSec = 60
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

	client := authv1.NewAuthAuthorityExternalAuthServiceClient(conn)
	callCtx, callCancel := context.WithTimeout(ctx, c.callTimeout)
	resp, err := client.ForwardBootstrapChallenge(
		callCtx,
		&authv1.BootstrapChallengeRequest{
			EntityType: entityType,
			EntityId:   strings.TrimSpace(req.EntityID),
			KeyId:      strings.TrimSpace(req.KeyID),
			Audience:   strings.TrimSpace(req.Audience),
			ClientId:   strings.TrimSpace(req.ClientID),
			GatewayId:  strings.TrimSpace(req.GatewayID),
			SourceIp:   strings.TrimSpace(req.SourceIP),
			UserAgent:  strings.TrimSpace(req.UserAgent),
			RequestId:  strings.TrimSpace(req.RequestID),
			TraceId:    strings.TrimSpace(req.TraceID),
			TtlSec:     ttlSec,
		},
	)
	callCancel()
	if err != nil {
		return nil, fmt.Errorf("forward bootstrap challenge rpc failed: %w", err)
	}

	return mapProtoChallengePayloadToGatewayModel(resp.GetChallenge())
}

func (c *ExternalAuthRPCClient) ForwardBootstrapAuthenticate(
	ctx context.Context,
	req *authmodel.BootstrapAuthRequest,
) (*authmodel.BootstrapAuthResult, error) {
	if req == nil {
		return nil, fmt.Errorf("bootstrap authenticate request is nil")
	}
	if c.endpoint == "" {
		return nil, fmt.Errorf("auth authority endpoint is required")
	}

	challengeID := req.Challenge.ChallengeID
	if challengeID == uuid.Nil {
		return nil, fmt.Errorf("challenge_id is required")
	}
	challengeEntityType, err := mapEntityType(string(req.Challenge.EntityType))
	if err != nil {
		return nil, err
	}
	signatureAlgorithm, err := mapGatewaySignatureAlgorithmToProto(req.Signed.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}
	signedChallengeID := req.Signed.ChallengeID
	if signedChallengeID == uuid.Nil {
		signedChallengeID = challengeID
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

	client := authv1.NewAuthAuthorityExternalAuthServiceClient(conn)
	callCtx, callCancel := context.WithTimeout(ctx, c.callTimeout)
	resp, err := client.ForwardBootstrapAuthenticate(
		callCtx,
		&authv1.BootstrapAuthenticateRequest{
			Challenge: &authv1.ChallengePayload{
				ChallengeId: challengeID.String(),
				Issuer:      strings.TrimSpace(req.Challenge.Issuer),
				Audience:    strings.TrimSpace(req.Challenge.Audience),
				EntityType:  challengeEntityType,
				EntityId:    strings.TrimSpace(req.Challenge.EntityID),
				KeyId:       strings.TrimSpace(req.Challenge.KeyID),
				Nonce:       strings.TrimSpace(req.Challenge.Nonce),
				IssuedAtMs:  req.Challenge.IssuedAt.UnixMilli(),
				ExpiresAtMs: req.Challenge.ExpiresAt.UnixMilli(),
			},
			Signed: &authv1.SignedChallengeResponse{
				ChallengeId:        signedChallengeID.String(),
				KeyId:              strings.TrimSpace(req.Signed.KeyID),
				SignatureAlgorithm: signatureAlgorithm,
				Signature:          strings.TrimSpace(req.Signed.Signature),
				SignedAtMs:         req.Signed.SignedAt.UnixMilli(),
			},
			Scopes:                 append([]string(nil), req.Scopes...),
			Role:                   strings.TrimSpace(req.Role),
			RequireDownstreamToken: req.RequireDownstreamToken,
		},
	)
	callCancel()
	if err != nil {
		return nil, fmt.Errorf("forward bootstrap authenticate rpc failed: %w", err)
	}

	stage := authmodel.BootstrapStage(normalizeBootstrapStage(resp.GetStage()))
	if stage == "" {
		return nil, fmt.Errorf("forward bootstrap authenticate response missing stage")
	}

	result := &authmodel.BootstrapAuthResult{
		Stage:           stage,
		Identity:        mapProtoIdentityToGatewayModel(resp.GetIdentity()),
		Session:         mapProtoSessionToModel(resp.GetSession()),
		ActiveCommKeyID: strings.TrimSpace(resp.GetActiveCommKeyId()),
		IssuedAt:        fromUnixMillis(resp.GetIssuedAtMs()),
		ExpiresAt:       fromUnixMillis(resp.GetExpiresAtMs()),
	}
	if tokens := resp.GetTokens(); tokens != nil {
		result.Tokens = authmodel.TokenBundle{
			AccessToken:     mapProtoIssuedTokenToGatewayModel(tokens.GetAccessToken()),
			RefreshToken:    mapProtoIssuedTokenToGatewayModel(tokens.GetRefreshToken()),
			DownstreamToken: mapProtoIssuedTokenToGatewayModel(tokens.GetDownstreamToken()),
		}
	}

	return result, nil
}

func mapProtoIdentityToGatewayModel(identity *authv1.IdentityContext) *authmodel.IdentityContext {
	if identity == nil {
		return nil
	}

	entityType := commonmodel.EntityType("")
	entityID := ""
	principalID := ""
	if principal := identity.GetPrincipal(); principal != nil {
		entityType = mapProtoEntityTypeToModel(principal.GetEntityType())
		entityID = strings.TrimSpace(principal.GetEntityId())
		principalID = strings.TrimSpace(principal.GetPrincipalId())
	}
	principal := authmodel.Principal{
		EntityType: entityType,
		EntityID:   entityID,
	}
	if principalID == "" {
		principalID = strings.TrimSpace(principal.PrincipalID())
	}

	return &authmodel.IdentityContext{
		Principal:     principal,
		EntityType:    entityType,
		EntityID:      entityID,
		PrincipalID:   principalID,
		SessionID:     parseUUIDOrNil(identity.GetSessionId()),
		TokenID:       parseUUIDOrNil(identity.GetTokenId()),
		TokenFamilyID: parseUUIDOrNil(identity.GetTokenFamilyId()),
		TokenType:     authmodel.TokenAccess,
		Role:          strings.TrimSpace(identity.GetRole()),
		Scopes:        append([]string(nil), identity.GetScopes()...),
		AuthMethod:    authmodel.AuthMethod(strings.TrimSpace(identity.GetAuthMethod())),
		SourceIP:      strings.TrimSpace(identity.GetSourceIp()),
		ClientID:      strings.TrimSpace(identity.GetClientId()),
		GatewayID:     strings.TrimSpace(identity.GetGatewayId()),
		SourceService: strings.TrimSpace(identity.GetSourceService()),
		TargetService: strings.TrimSpace(identity.GetTargetService()),
		RequestID:     strings.TrimSpace(identity.GetRequestId()),
		TraceID:       strings.TrimSpace(identity.GetTraceId()),
		IssuedAt:      fromUnixMillis(identity.GetIssuedAtMs()),
		ExpiresAt:     fromUnixMillis(identity.GetExpiresAtMs()),
	}
}

func mapProtoIssuedTokenToGatewayModel(token *authv1.IssuedToken) *authmodel.IssuedToken {
	if token == nil {
		return nil
	}
	resolvedType := mapProtoTokenTypeToGatewayModel(token.GetTokenType())
	return &authmodel.IssuedToken{
		Raw:     strings.TrimSpace(token.GetRaw()),
		Type:    resolvedType,
		Storage: authmodel.TokenStorageCache,
		Claims:  authmodel.TokenClaims{Type: resolvedType},
		TTLSec:  token.GetTtlSec(),
	}
}

func mapProtoTokenTypeToGatewayModel(value authv1.TokenType) authmodel.TokenType {
	switch value {
	case authv1.TokenType_TOKEN_TYPE_ACCESS:
		return authmodel.TokenAccess
	case authv1.TokenType_TOKEN_TYPE_REFRESH:
		return authmodel.TokenRefresh
	case authv1.TokenType_TOKEN_TYPE_SERVICE:
		return authmodel.TokenService
	case authv1.TokenType_TOKEN_TYPE_DOWNSTREAM:
		return authmodel.TokenDownstream
	default:
		return ""
	}
}

func mapGatewaySignatureAlgorithmToProto(value commsecmodel.SignatureAlgorithm) (authv1.SignatureAlgorithm, error) {
	switch strings.TrimSpace(strings.ToLower(string(value))) {
	case string(commsecmodel.SignatureEd25519):
		return authv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519, nil
	case string(commsecmodel.SignatureECDSAP256SHA256):
		return authv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256, nil
	case string(commsecmodel.SignatureRSAPSSSHA256):
		return authv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_RSA_PSS_SHA256, nil
	default:
		return authv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_UNSPECIFIED, fmt.Errorf("unsupported signature algorithm: %q", strings.TrimSpace(string(value)))
	}
}

func mapProtoChallengePayloadToGatewayModel(payload *authv1.ChallengePayload) (*authmodel.ChallengePayload, error) {
	if payload == nil {
		return nil, fmt.Errorf("bootstrap challenge response payload is nil")
	}
	challengeID, err := parseUUIDStrict("challenge_id", payload.GetChallengeId())
	if err != nil {
		return nil, err
	}
	entityType := mapProtoEntityTypeToModel(payload.GetEntityType())
	if entityType == "" {
		return nil, fmt.Errorf("unsupported entity_type in challenge payload")
	}

	return &authmodel.ChallengePayload{
		ChallengeID: challengeID,
		Issuer:      strings.TrimSpace(payload.GetIssuer()),
		Audience:    strings.TrimSpace(payload.GetAudience()),
		EntityType:  entityType,
		EntityID:    strings.TrimSpace(payload.GetEntityId()),
		KeyID:       strings.TrimSpace(payload.GetKeyId()),
		Nonce:       strings.TrimSpace(payload.GetNonce()),
		IssuedAt:    fromUnixMillis(payload.GetIssuedAtMs()),
		ExpiresAt:   fromUnixMillis(payload.GetExpiresAtMs()),
	}, nil
}

func parseUUIDStrict(fieldName string, raw string) (uuid.UUID, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return uuid.Nil, fmt.Errorf("%s is required", fieldName)
	}
	parsed, err := uuid.Parse(trimmed)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid %s: %w", fieldName, err)
	}
	return parsed, nil
}
