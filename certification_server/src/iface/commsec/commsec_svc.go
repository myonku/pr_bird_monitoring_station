package commsec

import (
	commsecmodel "certification_server/src/models/commsec"
	"context"
)

// ICommSecurityService 定义服务间应用层加密通道管理接口。
type ICommSecurityService interface {
	// InitHandshake 发起 ECDHE 密钥协商，返回协商参数和服务端公钥信息。
	InitHandshake(ctx context.Context, req *commsecmodel.ECDHEHandshakeInitRequest) (*commsecmodel.ECDHEHandshakeInitResult, error)
	// CompleteHandshake 完成 ECDHE 密钥协商，验证客户端响应并建立安全通道。
	CompleteHandshake(ctx context.Context, req *commsecmodel.ECDHEHandshakeCompleteRequest) (*commsecmodel.ECDHEHandshakeCompleteResult, error)

	// 安全通道管理接口，供网关或其他服务创建、查询和撤销安全通道。
	UpsertChannel(ctx context.Context, req *commsecmodel.SecureChannelUpsertRequest) (*commsecmodel.SecureChannelSession, error)
	// GetChannel 查询安全通道信息，验证通道状态和权限。
	GetChannel(ctx context.Context, req *commsecmodel.SecureChannelQuery) (*commsecmodel.SecureChannelSession, error)
	// TouchChannel 更新安全通道信息，通常用于延长通道有效期或更新通道元数据。
	RevokeChannel(ctx context.Context, req *commsecmodel.SecureChannelRevokeRequest) error

	// EncryptByChannel 基于已建立的安全通道加密应用层消息。
	EncryptByChannel(ctx context.Context, req *commsecmodel.ChannelEncryptRequest) (*commsecmodel.ChannelEncryptResult, error)
	// DecryptByChannel 基于已建立的安全通道解密应用层消息。
	DecryptByChannel(ctx context.Context, req *commsecmodel.ChannelDecryptRequest) (string, error)
}
