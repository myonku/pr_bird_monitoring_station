package communication

import (
	"context"
	"fmt"
	"strings"
	"time"

	authv1 "gateway/src/gen/auth/v1"
	authif "gateway/src/iface/auth"
	authmodel "gateway/src/models/auth"
	commonmodel "gateway/src/models/common"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// RemoteAuthRPCClient 负责调用认证中心 remote_auth proto 服务。
type RemoteAuthRPCClient struct {
	endpoint    string
	dialTimeout time.Duration
	callTimeout time.Duration
}

func NewRemoteAuthRPCClient(endpoint string) *RemoteAuthRPCClient {
	return &RemoteAuthRPCClient{
		endpoint:    strings.TrimSpace(endpoint),
		dialTimeout: 3 * time.Second,
		callTimeout: 5 * time.Second,
	}
}

func (c *RemoteAuthRPCClient) VerifyToken(
	ctx context.Context,
	req *authif.TokenVerifyRequest,
) (*authmodel.TokenVerificationResult, error) {
	if req == nil {
		return nil, fmt.Errorf("token verify request is nil")
	}
	if c.endpoint == "" {
		return nil, fmt.Errorf("auth authority endpoint is required")
	}
	if strings.TrimSpace(req.RawToken) == "" {
		return nil, fmt.Errorf("raw token is required")
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

	client := authv1.NewAuthAuthorityRemoteAuthServiceClient(conn)
	callCtx, callCancel := context.WithTimeout(ctx, c.callTimeout)
	resp, err := client.VerifyToken(
		callCtx,
		&authv1.TokenVerifyRequest{
			RawToken:            strings.TrimSpace(req.RawToken),
			ExpectedTypes:       mapGatewayExpectedTokenTypesToProto(req.ExpectedTypes),
			ExpectedAudience:    strings.TrimSpace(req.ExpectedAudience),
			RequireScopes:       append([]string(nil), req.RequireScopes...),
			SourceService:       strings.TrimSpace(req.SourceService),
			TargetService:       strings.TrimSpace(req.TargetService),
			AllowExpiredSkewSec: req.AllowExpiredSkewSec,
		},
	)
	callCancel()
	if err != nil {
		return nil, fmt.Errorf("verify token rpc failed: %w", err)
	}

	return &authmodel.TokenVerificationResult{
		Valid:                resp.GetValid(),
		Status:               mapProtoTokenStatusToModel(resp.GetStatus()),
		RevalidationRequired: resp.GetRevalidationRequired(),
		FailureReason:        strings.TrimSpace(resp.GetFailureReason()),
	}, nil
}

func (c *RemoteAuthRPCClient) ValidateSession(
	ctx context.Context,
	req *authif.SessionValidateRequest,
) (*authmodel.Session, error) {
	if req == nil {
		return nil, fmt.Errorf("session validate request is nil")
	}
	if c.endpoint == "" {
		return nil, fmt.Errorf("auth authority endpoint is required")
	}
	if req.SessionID == uuid.Nil {
		return nil, fmt.Errorf("session id is required")
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

	client := authv1.NewAuthAuthorityRemoteAuthServiceClient(conn)
	callCtx, callCancel := context.WithTimeout(ctx, c.callTimeout)
	resp, err := client.ValidateSession(
		callCtx,
		&authv1.SessionValidateRequest{
			SessionId:     req.SessionID.String(),
			PrincipalId:   strings.TrimSpace(req.PrincipalID),
			RequireActive: req.RequireActive,
			MinVersion:    req.MinVersion,
		},
	)
	callCancel()
	if err != nil {
		return nil, fmt.Errorf("validate session rpc failed: %w", err)
	}

	return mapProtoSessionToModel(resp), nil
}

func mapGatewayExpectedTokenTypesToProto(raw []authmodel.TokenType) []authv1.TokenType {
	if len(raw) == 0 {
		return nil
	}

	out := make([]authv1.TokenType, 0, len(raw))
	for _, item := range raw {
		switch strings.TrimSpace(strings.ToLower(string(item))) {
		case string(authmodel.TokenAccess):
			out = append(out, authv1.TokenType_TOKEN_TYPE_ACCESS)
		case string(authmodel.TokenRefresh):
			out = append(out, authv1.TokenType_TOKEN_TYPE_REFRESH)
		case string(authmodel.TokenService):
			out = append(out, authv1.TokenType_TOKEN_TYPE_SERVICE)
		case string(authmodel.TokenDownstream):
			out = append(out, authv1.TokenType_TOKEN_TYPE_DOWNSTREAM)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func mapProtoTokenStatusToModel(status authv1.TokenStatus) authmodel.TokenStatus {
	switch status {
	case authv1.TokenStatus_TOKEN_STATUS_ACTIVE:
		return authmodel.TokenStatusActive
	case authv1.TokenStatus_TOKEN_STATUS_ROTATED:
		return authmodel.TokenStatusRotated
	case authv1.TokenStatus_TOKEN_STATUS_REVOKED:
		return authmodel.TokenStatusRevoked
	case authv1.TokenStatus_TOKEN_STATUS_EXPIRED:
		return authmodel.TokenStatusExpired
	default:
		return ""
	}
}

func mapProtoSessionToModel(proto *authv1.Session) *authmodel.Session {
	if proto == nil {
		return nil
	}

	entityType := mapProtoEntityTypeToModel(proto.GetEntityType())
	entityID := strings.TrimSpace(proto.GetEntityId())
	if entityType == "" || entityID == "" {
		if principal := proto.GetPrincipal(); principal != nil {
			if entityType == "" {
				entityType = mapProtoEntityTypeToModel(principal.GetEntityType())
			}
			if entityID == "" {
				entityID = strings.TrimSpace(principal.GetEntityId())
			}
		}
	}
	principal := authmodel.Principal{EntityType: entityType, EntityID: entityID}

	return &authmodel.Session{
		ID:             parseUUIDOrNil(proto.GetSessionId()),
		Principal:      principal,
		EntityType:     entityType,
		EntityID:       entityID,
		PrincipalID:    strings.TrimSpace(proto.GetPrincipalId()),
		Status:         mapProtoSessionStatusToModel(proto.GetStatus()),
		AuthMethod:     mapProtoAuthMethodToModel(proto.GetAuthMethod()),
		CreatedByIP:    strings.TrimSpace(proto.GetCreatedByIp()),
		LastSeenIP:     strings.TrimSpace(proto.GetLastSeenIp()),
		UserAgent:      strings.TrimSpace(proto.GetUserAgent()),
		ClientID:       strings.TrimSpace(proto.GetClientId()),
		GatewayID:      strings.TrimSpace(proto.GetGatewayId()),
		ScopeSnapshot:  append([]string(nil), proto.GetScopeSnapshot()...),
		RoleSnapshot:   strings.TrimSpace(proto.GetRoleSnapshot()),
		TokenFamilyID:  parseUUIDOrNil(proto.GetTokenFamilyId()),
		CreatedAt:      fromUnixMillis(proto.GetCreatedAtMs()),
		UpdatedAt:      fromUnixMillis(proto.GetUpdatedAtMs()),
		LastSeenAt:     fromUnixMillis(proto.GetLastSeenAtMs()),
		LastVerifiedAt: fromUnixMillis(proto.GetLastVerifiedAtMs()),
		NextRefreshAt:  fromUnixMillis(proto.GetNextRefreshAtMs()),
		ExpiresAt:      fromUnixMillis(proto.GetExpiresAtMs()),
		RevokedAt:      fromUnixMillis(proto.GetRevokedAtMs()),
		Version:        proto.GetVersion(),
	}
}

func mapProtoEntityTypeToModel(entityType authv1.EntityType) commonmodel.EntityType {
	switch entityType {
	case authv1.EntityType_ENTITY_TYPE_USER:
		return commonmodel.EntityUser
	case authv1.EntityType_ENTITY_TYPE_DEVICE:
		return commonmodel.EntityDevice
	case authv1.EntityType_ENTITY_TYPE_SERVICE:
		return commonmodel.EntityService
	default:
		return ""
	}
}

func mapProtoSessionStatusToModel(status authv1.SessionStatus) authmodel.SessionStatus {
	switch status {
	case authv1.SessionStatus_SESSION_STATUS_ACTIVE:
		return authmodel.SessionActive
	case authv1.SessionStatus_SESSION_STATUS_REVOKED:
		return authmodel.SessionRevoked
	case authv1.SessionStatus_SESSION_STATUS_EXPIRED:
		return authmodel.SessionExpired
	case authv1.SessionStatus_SESSION_STATUS_BLOCKED:
		return authmodel.SessionBlocked
	default:
		return ""
	}
}

func mapProtoAuthMethodToModel(method authv1.AuthMethod) authmodel.AuthMethod {
	switch method {
	case authv1.AuthMethod_AUTH_METHOD_PASSWORD:
		return authmodel.AuthMethodPassword
	case authv1.AuthMethod_AUTH_METHOD_DEVICE_SECRET:
		return authmodel.AuthMethodDeviceSecret
	case authv1.AuthMethod_AUTH_METHOD_SERVICE_SECRET:
		return authmodel.AuthMethodServiceSecret
	case authv1.AuthMethod_AUTH_METHOD_REFRESH_TOKEN:
		return authmodel.AuthMethodRefreshToken
	case authv1.AuthMethod_AUTH_METHOD_TOKEN_EXCHANGE:
		return authmodel.AuthMethodTokenExchange
	default:
		return ""
	}
}

func parseUUIDOrNil(raw string) uuid.UUID {
	value := strings.TrimSpace(raw)
	if value == "" {
		return uuid.Nil
	}
	parsed, err := uuid.Parse(value)
	if err != nil {
		return uuid.Nil
	}
	return parsed
}

func fromUnixMillis(value int64) time.Time {
	if value <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(value).UTC()
}
