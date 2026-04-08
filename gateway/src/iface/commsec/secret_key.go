package commsec

import (
	"context"
	commsecmodel "gateway/src/models/commsec"
)

// ISecretKeyService 定义密钥管理服务接口。
// 除了本地密钥读取外，还需要支持统一公钥目录查询。
type ISecretKeyService interface {
	// 返回当前服务器的公钥（X.509/SPKI格式）
	GetPublicKey(ctx context.Context) (commsecmodel.ServicePublicKeyRecord, error)
	// 返回当前服务器的私钥引用信息（私钥原文不出服务本地）
	GetPrivateKeyRef(ctx context.Context) (commsecmodel.LocalPrivateKeyRef, error)

	// LookupPublicKey 支持按 key_id、entity_id 或 owner 查询全局公钥目录。
	LookupPublicKey(ctx context.Context, req *commsecmodel.PublicKeyLookupRequest) (commsecmodel.PublicKeyLookupResult, error)
}
