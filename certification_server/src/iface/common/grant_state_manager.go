package common

import (
	"context"
	"time"

	authmodel "certification_server/src/models/auth"

	"github.com/google/uuid"
)

// GrantStatus 定义下游授权令牌的生命周期状态。
type GrantStatus string

const (
	GrantStatusActive  GrantStatus = "active"
	GrantStatusUsed    GrantStatus = "used"
	GrantStatusRevoked GrantStatus = "revoked"
	GrantStatusExpired GrantStatus = "expired"
)

// GrantStateRecord 是下游授权令牌的持久化快照。
type GrantStateRecord struct {
	GrantKey string

	SessionID   uuid.UUID
	TokenID     uuid.UUID
	PrincipalID string

	GatewayID     string
	SourceService string
	TargetService string

	Status GrantStatus

	IssuedAt  time.Time
	ExpiresAt time.Time
	UsedAt    time.Time
	UpdatedAt time.Time

	Metadata map[string]string
}

// IGrantStateManager 定义可选的下游授权状态管理。
type IGrantStateManager interface {
	SaveGrant(ctx context.Context, grant *authmodel.DownstreamAccessGrant) (string, error)
	LoadActiveGrant(ctx context.Context, tokenID uuid.UUID) (*GrantStateRecord, error)
	MarkGrantUsed(ctx context.Context, tokenID uuid.UUID, usedAt time.Time) error
	RevokeGrant(ctx context.Context, tokenID uuid.UUID, reason string) error
	PurgeExpiredGrants(ctx context.Context, before time.Time) (int64, error)
}
