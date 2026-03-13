package interfaces

// ISecretKeyService 定义了密钥管理服务的接口，包含生成密钥、获取密钥、更新密钥和删除密钥等方法。
type ISecretKeyService interface {
	// 返回当前服务器的公钥（X.509/SPKI格式）
	GetPublicKey() string
	// 返回当前服务器的私钥（PKCS8/PEM格式）
	GetPrivateKey() string
	// 后续可能需要提供密钥轮换、密钥版本管理等方法
}
