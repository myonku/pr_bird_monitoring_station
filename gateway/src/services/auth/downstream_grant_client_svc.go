package auth

import (
	"context"
	"time"

	authif "gateway/src/interfaces/auth"
	authmodel "gateway/src/models/auth"
	commsecmodel "gateway/src/models/commsec"
	modelsystem "gateway/src/models/system"

	"github.com/google/uuid"
)

var _ authif.IDownstreamGrantClient = (*DownstreamGrantClientService)(nil)

// DownstreamGrantClientService 在网关侧组装下游授权上下文。
type DownstreamGrantClientService struct{}

func NewDownstreamGrantClientService() *DownstreamGrantClientService {
	return &DownstreamGrantClientService{}
}

func (s *DownstreamGrantClientService) IssueDownstreamGrant(
	ctx context.Context, req *authmodel.DownstreamGrantRequest,
) (*authmodel.DownstreamAccessGrant, error) {
	_ = ctx
	if req == nil {
		return nil, &modelsystem.ErrDownstreamGrantRequestNil
	}
	if req.Identity.PrincipalID == "" {
		return nil, &modelsystem.ErrIdentityPrincipalRequired
	}
	if req.TargetService == "" {
		return nil, &modelsystem.ErrTargetServiceRequired
	}

	now := time.Now()
	ttl := req.TTLSec
	if ttl <= 0 {
		ttl = 120
	}

	binding := req.BindingType
	if binding == "" {
		if req.Identity.SessionID == uuid.Nil {
			binding = commsecmodel.ChannelBindingToken
		} else {
			binding = commsecmodel.ChannelBindingSession
		}
	}

	grant := &authmodel.DownstreamAccessGrant{
		GatewayID:       req.Identity.GatewayID,
		SourceService:   req.Identity.SourceService,
		TargetService:   req.TargetService,
		SessionID:       req.Identity.SessionID,
		TokenID:         req.Identity.TokenID,
		PrincipalID:     req.Identity.PrincipalID,
		BindingType:     binding,
		Scopes:          append([]string(nil), req.Identity.Scopes...),
		SecureChannelID: req.Identity.SecureChannelID,
		CipherSuite:     req.Identity.CipherSuite,
		IssuedAt:        now,
		ExpiresAt:       now.Add(time.Duration(ttl) * time.Second),
	}
	return grant, nil
}
