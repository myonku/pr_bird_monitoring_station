package common

import (
	iface "certification_server/src/iface/common"
	authmodel "certification_server/src/models/auth"
	commonmodel "certification_server/src/models/common"
	modelsystem "certification_server/src/models/system"
	"context"
	"strings"
)

var _ iface.IUserCredentialManager = (*UserCredentialService)(nil)

// UserCredentialService 提供用户凭证验证能力，避免上层直接调用底层数据库。
type UserCredentialService struct {
}

func NewUserCredentialService() *UserCredentialService {
	return &UserCredentialService{}
}

// TODO: 目前的实现仅做输入校验和最小的身份快照构建，后续需要接入实际的用户数据存储和密码验证逻辑。
func (s *UserCredentialService) ValidateCredentials(
	ctx context.Context,
	req iface.UserPwdCredentialRequest,
) (*iface.UserCredentialValidationResult, error) {
	_ = ctx

	username := strings.TrimSpace(req.Username)
	if username == "" {
		username = strings.TrimSpace(req.Email)
	}
	if username == "" {
		username = strings.TrimSpace(req.Phone)
	}
	if username == "" {
		return nil, &modelsystem.ErrUsernameRequired
	}
	if strings.TrimSpace(req.Password) == "" {
		return nil, &modelsystem.ErrPasswordRequired
	}

	principal := authmodel.Principal{
		EntityType: commonmodel.EntityUser,
		EntityID:   username,
	}

	return &iface.UserCredentialValidationResult{
		Principal: principal,
		Role:      "user",
		Scopes:    []string{"user:read"},
	}, nil

}
