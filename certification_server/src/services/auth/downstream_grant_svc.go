package auth

import (
	"context"
	"fmt"
	"time"

	interfaces "certification_server/src/interfaces/auth"
	authmodel "certification_server/src/models/auth"
	commsecmodel "certification_server/src/models/commsec"

	"github.com/google/uuid"
)

var _ interfaces.IDownstreamGrantService = (*DownstreamGrantService)(nil)

// DownstreamGrantService 负责根据认证上下文签发服务间下游访问授权。
type DownstreamGrantService struct{}

func NewDownstreamGrantService() *DownstreamGrantService {
	return &DownstreamGrantService{}
}

// IssueDownstreamGrant 根据认证上下文和目标服务签发下游访问授权。
func (s *DownstreamGrantService) IssueDownstreamGrant(
	ctx context.Context, req *authmodel.DownstreamGrantRequest,
) (*authmodel.DownstreamAccessGrant, error) {
	if req == nil {
		return nil, fmt.Errorf("downstream grant request is nil")
	}
	if req.Identity.PrincipalID == "" {
		return nil, fmt.Errorf("identity principal is required")
	}
	if req.TargetService == "" {
		return nil, fmt.Errorf("target service is required")
	}

	now := time.Now()
	ttlSec := req.TTLSec
	if ttlSec <= 0 {
		ttlSec = 120
	}

	bindingType := req.BindingType
	if bindingType == "" {
		bindingType = commsecmodel.ChannelBindingSession
		if req.Identity.SessionID == uuid.Nil {
			bindingType = commsecmodel.ChannelBindingToken
		}
	}

	grant := &authmodel.DownstreamAccessGrant{
		GatewayID:       req.Identity.GatewayID,
		SourceService:   req.Identity.SourceService,
		TargetService:   req.TargetService,
		SessionID:       req.Identity.SessionID,
		TokenID:         req.Identity.TokenID,
		PrincipalID:     req.Identity.PrincipalID,
		BindingType:     bindingType,
		Scopes:          append([]string(nil), req.Identity.Scopes...),
		SecureChannelID: req.Identity.SecureChannelID,
		CipherSuite:     req.Identity.CipherSuite,
		IssuedAt:        now,
		ExpiresAt:       now.Add(time.Duration(ttlSec) * time.Second),
	}

	return grant, nil
}
