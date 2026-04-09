package communication

import commsecmodel "gateway/src/models/commsec"

// SecureChannelEnsureRequest 是主动通信方出站前确保通道可用的共享请求契约。
type SecureChannelEnsureRequest struct {
	ChannelClass commsecmodel.ChannelClass
	SecurityMode commsecmodel.ChannelSecurityMode

	Query SecureChannelQuery

	HandshakeInit *ECDHEHandshakeInitRequest

	RequireActive    bool
	ForceReHandshake bool
}

// EncryptedPayload 是按通道加密结果共享契约。
type EncryptedPayload struct {
	CipherText string
	Meta       commsecmodel.EncryptedMessageMeta
}
