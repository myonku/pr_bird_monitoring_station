package commsec

import (
	"context"
	commsecmodel "gateway/src/models/commsec"
)

// ICommSecurityService 定义服务间应用层加密通道管理接口。
type ICommSecurityService interface {
	// InitHandshake 发起 ECDHE 握手初始化。
	InitHandshake(ctx context.Context, req *commsecmodel.ECDHEHandshakeInitRequest) (*commsecmodel.ECDHEHandshakeInitResult, error)
	// CompleteHandshake 完成 ECDHE 握手并返回握手结果。
	CompleteHandshake(ctx context.Context, req *commsecmodel.ECDHEHandshakeCompleteRequest) (*commsecmodel.ECDHEHandshakeCompleteResult, error)

	// UpsertChannel 建立或更新本地安全通道缓存。
	UpsertChannel(ctx context.Context, req *commsecmodel.SecureChannelUpsertRequest) (*commsecmodel.SecureChannelSession, error)
	// GetChannel 按查询条件获取安全通道。
	GetChannel(ctx context.Context, req *commsecmodel.SecureChannelQuery) (*commsecmodel.SecureChannelSession, error)
	// RevokeChannel 撤销本地安全通道。
	RevokeChannel(ctx context.Context, req *commsecmodel.SecureChannelRevokeRequest) error
}
