package commsec

import (
	commsecmodel "certification_server/src/models/commsec"
	"context"
)

// ISecretKeyService 定义密钥管理服务接口。
// 除了本地密钥读取外，还需要支持按 owner 或 key id 查询任意实体公钥。
type ISecretKeyService interface {
	// 返回当前服务器的公钥（X.509/SPKI格式）
	GetPublicKey(ctx context.Context) (commsecmodel.ServicePublicKeyRecord, error)
	// 返回当前服务器的私钥引用信息（私钥原文不出服务本地）
	GetPrivateKeyRef(ctx context.Context) (commsecmodel.LocalPrivateKeyRef, error)

	// 按 key id 查询全局公钥目录
	GetPublicKeyByKeyID(ctx context.Context, keyID string) (commsecmodel.PublicKeyLookupResult, error)
	// 按 owner 查询全局公钥目录
	GetPublicKeysByOwner(ctx context.Context, owner commsecmodel.ServiceKeyOwner) ([]commsecmodel.ServicePublicKeyRecord, error)
}
