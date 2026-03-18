package communication

import (
	"context"
	authmodel "gateway/src/models/auth"
	commsecmodel "gateway/src/models/commsec"
)

// OutboundForwardRequest 表示一次内部服务转发请求。
type OutboundForwardRequest struct {
	TargetService string
	Endpoint      string
	Method        string
	RPCMethod     string
	TimeoutMS     int64
	Path          string
	Headers       map[string]string
	Body          []byte
	Query         map[string]string
}

// OutboundForwardResponse 表示内部服务转发响应。
type OutboundForwardResponse struct {
	StatusCode int
	Headers    map[string]string
	Body       []byte
}

// OutboundSecurityContext 表示转发阶段所需安全上下文。
// 引用: src/interfaces/communication/outbound_security.go。
type OutboundSecurityContext struct {
	Grant   *authmodel.DownstreamAccessGrant
	Channel *commsecmodel.SecureChannelSession

	EncryptedPayload []byte
	EncryptedMeta    *commsecmodel.EncryptedMessageMeta
}

// IOutboundForwarder 负责把请求发送给内部服务。
// 边界约束: 仅消费已准备好的安全上下文，不负责 bootstrap/grant/handshake 编排。
// 引用: src/interfaces/auth/bootstrap_flow.go, src/interfaces/commsec/commsec_svc.go。
type IOutboundForwarder interface {
	Forward(ctx context.Context, req *OutboundForwardRequest, security *OutboundSecurityContext) (*OutboundForwardResponse, error)
}
