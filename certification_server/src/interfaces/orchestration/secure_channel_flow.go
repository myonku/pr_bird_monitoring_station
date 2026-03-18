package orchestration

import (
	commsecmodel "certification_server/src/models/commsec"
	"context"
)

// HandshakeStartFlowRequest 表示握手初始化编排输入。
type HandshakeStartFlowRequest struct {
	InitRequest *commsecmodel.ECDHEHandshakeInitRequest
}

// HandshakeFinishFlowRequest 表示握手完成编排输入。
type HandshakeFinishFlowRequest struct {
	CompleteRequest *commsecmodel.ECDHEHandshakeCompleteRequest
}

// HandshakeFlowResult 表示握手编排结果。
type HandshakeFlowResult struct {
	InitResult     *commsecmodel.ECDHEHandshakeInitResult
	CompleteResult *commsecmodel.ECDHEHandshakeCompleteResult
	Channel        *commsecmodel.SecureChannelSession
}

// SecurePayloadFlowResult 表示加解密编排结果。
type SecurePayloadFlowResult struct {
	Encrypted *commsecmodel.ChannelEncryptResult
	PlainText string
}

// ICommSecurityOrchestrator 定义认证中心通信安全统合编排接口。
// 引用: certification_server/src/interfaces/commsec/commsec_svc.go,
// certification_server/src/interfaces/commsec/secret_key.go。
// 引用标准: RFC 5116 (AEAD), RFC 8446 (协商参数驱动密码套件选择)。
type ICommSecurityOrchestrator interface {
	// StartHandshakeFlow 执行握手起始编排：算法协商策略 + 握手初始化。
	StartHandshakeFlow(ctx context.Context, req *HandshakeStartFlowRequest) (*HandshakeFlowResult, error)
	// FinishHandshakeFlow 执行握手完成编排：签名校验 + 密钥派生 + 通道落地。
	FinishHandshakeFlow(ctx context.Context, req *HandshakeFinishFlowRequest) (*HandshakeFlowResult, error)

	// EncryptForTransport 执行传输前加密编排，供 gRPC 出站拦截器调用。
	EncryptForTransport(ctx context.Context, req *commsecmodel.ChannelEncryptRequest) (*SecurePayloadFlowResult, error)
	// DecryptFromTransport 执行传输后解密编排，供 gRPC 入站拦截器调用。
	DecryptFromTransport(ctx context.Context, req *commsecmodel.ChannelDecryptRequest) (*SecurePayloadFlowResult, error)

	// RevokeChannelFlow 执行安全通道撤销编排。
	RevokeChannelFlow(ctx context.Context, req *commsecmodel.SecureChannelRevokeRequest) error
}
