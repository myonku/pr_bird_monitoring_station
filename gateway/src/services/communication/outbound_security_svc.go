package communication

import (
	"context"

	authif "gateway/src/interfaces/auth"
	commsecif "gateway/src/interfaces/commsec"
	commif "gateway/src/interfaces/communication"
	authmodel "gateway/src/models/auth"
	commsecmodel "gateway/src/models/commsec"
	modelsystem "gateway/src/models/system"
)

var _ commif.IOutboundInvocationSecurity = (*OutboundInvocationSecurityService)(nil)
var _ commif.IOutboundAuthCoordinator = (*OutboundAuthCoordinator)(nil)
var _ commif.IOutboundChannelCoordinator = (*OutboundChannelCoordinator)(nil)

// OutboundAuthCoordinator 聚合 bootstrap 与 grant 调用。
type OutboundAuthCoordinator struct {
	BootstrapFlow authif.IBootstrapFlowCoordinator
	GrantClient   authif.IDownstreamGrantClient
}

func (c *OutboundAuthCoordinator) EnsureBootstrapReady(
	ctx context.Context, req *authmodel.ChallengeRequest,
) (*authmodel.BootstrapAuthResult, error) {
	if c == nil || c.BootstrapFlow == nil {
		return nil, &modelsystem.ErrBootstrapCoordinatorRequired
	}
	if req == nil {
		return nil, &modelsystem.ErrChallengeRequestNil
	}
	return c.BootstrapFlow.EnsureReady(ctx, &authmodel.BootstrapEnsureReadyRequest{ChallengeRequest: req})
}

func (c *OutboundAuthCoordinator) IssueDownstreamGrant(
	ctx context.Context, req *authmodel.DownstreamGrantRequest,
) (*authmodel.DownstreamAccessGrant, error) {
	if c == nil || c.GrantClient == nil {
		return nil, &modelsystem.ErrDownstreamGrantClientRequired
	}
	return c.GrantClient.IssueDownstreamGrant(ctx, req)
}

// OutboundChannelCoordinator 适配 commsec 端口到安全编排端口。
type OutboundChannelCoordinator struct {
	CommSecSvc commsecif.ICommSecurityService
}

func (c *OutboundChannelCoordinator) EnsureChannel(
	ctx context.Context, req *commsecmodel.SecureChannelEnsureRequest,
) (*commsecmodel.SecureChannelSession, error) {
	if c == nil || c.CommSecSvc == nil {
		return nil, &modelsystem.ErrCommSecurityServiceRequired
	}
	return c.CommSecSvc.EnsureChannel(ctx, req)
}

func (c *OutboundChannelCoordinator) EncryptForChannel(
	ctx context.Context, req *commsecmodel.EncryptForChannelRequest,
) (*commsecmodel.EncryptedPayload, error) {
	if c == nil || c.CommSecSvc == nil {
		return nil, &modelsystem.ErrCommSecurityServiceRequired
	}
	return c.CommSecSvc.EncryptForChannel(ctx, req)
}

// OutboundInvocationSecurityService 负责把 grant + channel + 可选密文整合为统一上下文。
type OutboundInvocationSecurityService struct {
	AuthCoordinator    commif.IOutboundAuthCoordinator
	ChannelCoordinator commif.IOutboundChannelCoordinator
}

func (s *OutboundInvocationSecurityService) Prepare(
	ctx context.Context,
	req *commif.OutboundInvocationRequest,
) (*commif.OutboundInvocationContext, error) {
	if s == nil || s.AuthCoordinator == nil || s.ChannelCoordinator == nil {
		return nil, &modelsystem.ErrOutboundSecurityDependenciesRequired
	}
	if req == nil || req.GrantRequest == nil || req.ChannelQuery == nil {
		return nil, &modelsystem.ErrOutboundInvocationRequestInvalid
	}

	grant, err := s.AuthCoordinator.IssueDownstreamGrant(ctx, req.GrantRequest)
	if err != nil {
		return nil, err
	}
	channel, err := s.ChannelCoordinator.EnsureChannel(ctx, &commsecmodel.SecureChannelEnsureRequest{
		Query:            *req.ChannelQuery,
		HandshakeInit:    req.HandshakeInit,
		RequireActive:    true,
		ForceReHandshake: false,
	})
	if err != nil {
		return nil, err
	}

	result := &commif.OutboundInvocationContext{Grant: grant, Channel: channel}
	if req.RequireEncryptedPayload {
		encrypted, encErr := s.ChannelCoordinator.EncryptForChannel(ctx, &commsecmodel.EncryptForChannelRequest{
			ChannelID:      channel.ID,
			Payload:        req.Payload,
			AdditionalData: req.AdditionalData,
		})
		if encErr != nil {
			return nil, encErr
		}
		result.CipherText = encrypted.CipherText
		meta := encrypted.Meta
		result.Meta = &meta
	}
	return result, nil
}
