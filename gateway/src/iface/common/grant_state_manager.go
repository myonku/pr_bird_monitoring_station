package common

import (
	"context"
	"time"

	authmodel "gateway/src/models/auth"

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

// TODO: 网关的 IGrantStateManager 存在疑似有误。网关应当从认证中心获取授权状态，而非直接管理授权状态。
// 需要进一步确认设计意图，是否需要在网关侧也实现一套授权状态管理接口。
// IGrantStateManager 定义可选的下游授权状态管理。
type IGrantStateManager interface {
	// SaveGrant 在认证中心颁发下游授权时保存状态记录，并返回一个唯一的 GrantKey 供后续查询和管理使用。
	SaveGrant(ctx context.Context, grant *authmodel.DownstreamAccessGrant) (string, error)
	// LoadActiveGrant 加载有效的下游授权状态记录。
	LoadActiveGrant(ctx context.Context, tokenID uuid.UUID) (*GrantStateRecord, error)
	// MarkGrantUsed 标记下游授权为已使用。
	MarkGrantUsed(ctx context.Context, tokenID uuid.UUID, usedAt time.Time) error
	// RevokeGrant 撤销下游授权，记录撤销原因。
	RevokeGrant(ctx context.Context, tokenID uuid.UUID, reason string) error
	// PurgeExpiredGrants 定期清理过期的授权记录，返回清理的记录数。
	PurgeExpiredGrants(ctx context.Context, before time.Time) (int64, error)
}
