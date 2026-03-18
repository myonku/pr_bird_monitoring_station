package security

import (
	"context"
	"errors"

	commif "gateway/src/interfaces/communication"
	commsecmodel "gateway/src/models/commsec"
)

// IPrepareOutboundSecurityUsecase 定义出站安全准备用例接口。
type IPrepareOutboundSecurityUsecase interface {
	Execute(ctx context.Context, req *commif.OutboundInvocationRequest) (*commif.OutboundInvocationContext, error)
}

// PrepareOutboundSecurityUsecase 组合 auth 与 commsec 端口完成安全准备。
type PrepareOutboundSecurityUsecase struct {
	AuthCoordinator    commif.IOutboundAuthCoordinator
	ChannelCoordinator commif.IOutboundChannelCoordinator
}

// Execute 输出可直接用于出站调用的统一安全上下文。
func (u *PrepareOutboundSecurityUsecase) Execute(
	ctx context.Context,
	req *commif.OutboundInvocationRequest,
) (*commif.OutboundInvocationContext, error) {
	if u == nil || u.AuthCoordinator == nil || u.ChannelCoordinator == nil {
		return nil, errors.New("outbound security dependencies are required")
	}
	if req == nil || req.GrantRequest == nil || req.ChannelQuery == nil {
		return nil, errors.New("outbound invocation request is invalid")
	}

	grant, err := u.AuthCoordinator.IssueDownstreamGrant(ctx, req.GrantRequest)
	if err != nil {
		return nil, err
	}

	ensureReq := &commsecmodel.SecureChannelEnsureRequest{
		Query:            *req.ChannelQuery,
		HandshakeInit:    req.HandshakeInit,
		RequireActive:    true,
		ForceReHandshake: false,
	}
	channel, err := u.ChannelCoordinator.EnsureChannel(ctx, ensureReq)
	if err != nil {
		return nil, err
	}

	result := &commif.OutboundInvocationContext{
		Grant:   grant,
		Channel: channel,
	}

	if req.RequireEncryptedPayload {
		encrypted, encErr := u.ChannelCoordinator.EncryptForChannel(ctx, &commsecmodel.EncryptForChannelRequest{
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
