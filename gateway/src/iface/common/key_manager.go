package common

import (
	"context"

	commsecmodel "gateway/src/models/commsec"
)

// ISecretKeyManager 定义密钥管理相关操作。
type ISecretKeyManager interface {
	// GetPublicKey 获取本地服务的公钥信息。
	GetPublicKey(ctx context.Context) (commsecmodel.ServicePublicKeyRecord, error)
	// GetPrivateKeyRef 获取本地服务的私钥引用信息。
	GetPrivateKeyRef(ctx context.Context) (commsecmodel.LocalPrivateKeyRef, error)
	// 通过指定信息查询公钥记录，支持多维度查询条件（如实体ID、密钥ID等）。
	LookupPublicKey(ctx context.Context, req *commsecmodel.PublicKeyLookupRequest) (commsecmodel.PublicKeyLookupResult, error)
}
