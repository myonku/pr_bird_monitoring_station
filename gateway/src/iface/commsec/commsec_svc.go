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
	// EnsureChannel 确保指定上下文已有可用安全通道，不可用时主动触发握手并建链。
	EnsureChannel(ctx context.Context, req *commsecmodel.SecureChannelEnsureRequest) (*commsecmodel.SecureChannelSession, error)

	// UpsertChannel 建立或更新本地安全通道缓存。
	UpsertChannel(ctx context.Context, req *commsecmodel.SecureChannelUpsertRequest) (*commsecmodel.SecureChannelSession, error)
	// GetChannel 按查询条件获取安全通道。
	GetChannel(ctx context.Context, req *commsecmodel.SecureChannelQuery) (*commsecmodel.SecureChannelSession, error)
	// RevokeChannel 撤销本地安全通道。
	RevokeChannel(ctx context.Context, req *commsecmodel.SecureChannelRevokeRequest) error

	// EncryptForChannel 以通道上下文加密出站业务载荷，供 gRPC 客户端拦截器调用。
	// 引用: RFC 5116 (AEAD 接口要求), RFC 8446 (握手协商驱动套件选择)。
	EncryptForChannel(ctx context.Context, req *commsecmodel.EncryptForChannelRequest) (*commsecmodel.EncryptedPayload, error)
	// DecryptFromChannel 以通道上下文解密入站业务载荷，供 gRPC 服务端拦截器调用。
	// 引用: RFC 5116 (AEAD 接口要求), gRPC Metadata 语义约束。
	DecryptFromChannel(ctx context.Context, req *commsecmodel.DecryptFromChannelRequest) (*commsecmodel.DecryptedPayload, error)
}
