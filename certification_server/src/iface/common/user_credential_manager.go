package common

import (
	"context"

	authmodel "certification_server/src/models/auth"
)

// UserPwdCredentialRequest 是用户密码凭证验证的请求结构。
type UserPwdCredentialRequest struct {
	Username    string // 可选的用户名、邮箱或手机号，后端服务应该支持多种方式进行用户身份识别。
	Email       string // 可选的用户名、邮箱或手机号，后端服务应该支持多种方式进行用户身份识别。
	Phone       string // 可选的用户名、邮箱或手机号，后端服务应该支持多种方式进行用户身份识别。
	Password    string // 明文密码，后端服务应该使用安全的哈希算法进行验证，不应直接存储或传输明文密码。
	Timestamp   int64  // 请求时间戳，单位为秒，用于防止重放攻击等安全校验。
	Fingerprint string // 可选的设备指纹信息，用于增强安全校验和风险评估。
}

// UserCredentialValidationResult 是用户凭证校验输出。
type UserCredentialValidationResult struct {
	Principal authmodel.Principal
	Role      string
	Scopes    []string
}

// IUserCredentialManager 定义用户凭证验证相关操作。
// 原则上只进行认证中心所需的认证相关校验，不负责具体的用户信息管理和权限管理等功能。
type IUserCredentialManager interface {
	// ValidateCredentials 验证用户凭证并返回最小身份快照，供编排层组装会话与令牌。
	ValidateCredentials(ctx context.Context, req UserPwdCredentialRequest) (*UserCredentialValidationResult, error)
}
