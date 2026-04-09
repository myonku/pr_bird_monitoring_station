package common

import (
	"context"
	"time"

	authmodel "gateway/src/models/auth"
	commonmodel "gateway/src/models/common"

	"github.com/google/uuid"
)

// ModuleCredentialSnapshot 描述网关本模块认证凭证快照。
type ModuleCredentialSnapshot struct {
	PrincipalID string
	EntityType  commonmodel.EntityType
	EntityID    string

	SessionID     uuid.UUID
	TokenFamilyID uuid.UUID

	AccessTokenRaw  string
	RefreshTokenRaw string

	Scopes []string
	Role   string
	Stage  authmodel.BootstrapStage

	ActiveCommKeyID string

	IssuedAt  time.Time
	ExpiresAt time.Time
	UpdatedAt time.Time

	Metadata map[string]string
}

// ILocalCredentialManager 定义网关本模块凭证快照管理能力。
type ILocalCredentialManager interface {
	// SaveBootstrapCredential 写入 bootstrap 成功后的凭证快照。
	SaveBootstrapCredential(ctx context.Context, snapshot *ModuleCredentialSnapshot) (string, error)
	// LoadActiveCredential 读取主体当前可用的凭证快照。
	LoadActiveCredential(ctx context.Context, principalID string) (*ModuleCredentialSnapshot, error)
	// MarkCredentialExpired 标记主体凭证为过期状态。
	MarkCredentialExpired(ctx context.Context, principalID string, reason string) error
	// RevokeCredential 撤销主体凭证并清理可用状态。
	RevokeCredential(ctx context.Context, principalID string, reason string) error
}
