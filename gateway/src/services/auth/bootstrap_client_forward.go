package auth

import (
	"context"
	"strings"

	authif "gateway/src/interfaces/auth"
	authmodel "gateway/src/models/auth"
	modelsystem "gateway/src/models/system"
)

var _ authif.IBootstrapClient = (*ForwardBootstrapClient)(nil)

// ForwardBootstrapClient 只负责把 bootstrap 请求转发给认证中心。
type ForwardBootstrapClient struct {
	Authority authif.IAuthGatewayAuthorityClient

	EntityType authmodel.EntityType
	EntityID   string
}

func NewForwardBootstrapClient(
	authority authif.IAuthGatewayAuthorityClient,
	entityType authmodel.EntityType,
	entityID string,
) *ForwardBootstrapClient {
	if entityType == "" {
		entityType = authmodel.EntityService
	}
	return &ForwardBootstrapClient{
		Authority:  authority,
		EntityType: entityType,
		EntityID:   strings.TrimSpace(entityID),
	}
}

func (c *ForwardBootstrapClient) InitChallenge(
	ctx context.Context,
	req *authmodel.ChallengeRequest,
) (*authmodel.ChallengePayload, error) {
	if c == nil || c.Authority == nil {
		return nil, &modelsystem.ErrBootstrapClientRequired
	}
	return c.Authority.InitChallenge(ctx, req)
}

func (c *ForwardBootstrapClient) AuthenticateBootstrap(
	ctx context.Context,
	req *authmodel.BootstrapAuthRequest,
) (*authmodel.BootstrapAuthResult, error) {
	if c == nil || c.Authority == nil {
		return nil, &modelsystem.ErrBootstrapClientRequired
	}
	return c.Authority.AuthenticateBootstrap(ctx, req)
}

func (c *ForwardBootstrapClient) GetBootstrapStage(
	ctx context.Context,
) (authmodel.BootstrapStage, error) {
	if c == nil || c.Authority == nil {
		return "", &modelsystem.ErrBootstrapClientRequired
	}
	entityID := strings.TrimSpace(c.EntityID)
	if entityID == "" {
		return authmodel.BootstrapStageUninitialized, &modelsystem.ErrEntityIDRequired
	}
	entityType := c.EntityType
	if entityType == "" {
		entityType = authmodel.EntityService
	}
	return c.Authority.GetBootstrapStage(ctx, entityType, entityID)
}
