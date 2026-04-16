package common

import (
	iface "certification_server/src/iface/common"
	authmodel "certification_server/src/models/auth"
	commonmodel "certification_server/src/models/common"
	modelsystem "certification_server/src/models/system"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"certification_server/src/repo"
	"certification_server/src/utils"
)

var _ iface.IUserCredentialManager = (*UserCredentialService)(nil)

// UserCredentialService 提供用户凭证验证能力，避免上层直接调用底层数据库。
type UserCredentialService struct {
	mysql       *repo.MySQLClient
	cryptoUtils *utils.CryptoUtils
}

func NewUserCredentialService(mysql *repo.MySQLClient) *UserCredentialService {
	return &UserCredentialService{mysql: mysql, cryptoUtils: &utils.CryptoUtils{}}
}

func (s *UserCredentialService) ValidateCredentials(
	ctx context.Context,
	req iface.UserPwdCredentialRequest,
) (*iface.UserCredentialValidationResult, error) {
	_ = ctx

	if s.mysql == nil {
		return nil, &modelsystem.ErrMySQLNotConfigured
	}

	username := strings.TrimSpace(req.Username)
	email := strings.TrimSpace(req.Email)
	phone := strings.TrimSpace(req.Phone)
	if username == "" && email == "" && phone == "" {
		return nil, &modelsystem.ErrUsernameRequired
	}
	if strings.TrimSpace(req.Password) == "" {
		return nil, &modelsystem.ErrPasswordRequired
	}

	record, err := s.lookupUserRecord(ctx, username, email, phone)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, &modelsystem.ErrUserNotFound
	}

	if err := s.validateUserStatus(record.Status, record.Metadata); err != nil {
		return nil, err
	}

	cryptoUtils := s.cryptoUtils
	if cryptoUtils == nil {
		cryptoUtils = &utils.CryptoUtils{}
	}
	if err := cryptoUtils.VerifyPasswordHash(record.HashAlgorithm, record.PasswordHash, req.Password); err != nil {
		return nil, err
	}

	profileID, err := uuid.Parse(strings.TrimSpace(record.UserProfileID))
	if err != nil {
		return nil, fmt.Errorf("parse user profile id failed: %w", err)
	}

	principal := authmodel.Principal{
		EntityType: commonmodel.EntityUser,
		EntityID:   record.UserName,
	}
	if strings.TrimSpace(principal.EntityID) == "" {
		principal.EntityID = username
	}

	role := strings.TrimSpace(record.Role)
	if role == "" {
		role = "user"
	}

	return &iface.UserCredentialValidationResult{
		Principal:     principal,
		UserProfileID: profileID,
		Role:          role,
		Scopes:        s.defaultUserScopes(role),
	}, nil

}

type userCredentialRecord struct {
	UserProfileID string `db:"user_profile_id"`
	UserName      string `db:"user_name"`
	Role          string `db:"role"`
	PasswordHash  string `db:"password_hash"`
	HashAlgorithm string `db:"hash_algorithm"`
	Status        string `db:"status"`
	Metadata      []byte `db:"metadata"`
}

func (s *UserCredentialService) lookupUserRecord(
	ctx context.Context,
	username, email, phone string,
) (*userCredentialRecord, error) {
	queries := []struct {
		column string
		value  string
	}{
		{column: "user_name", value: username},
		{column: "email", value: email},
		{column: "phone", value: phone},
	}

	for _, queryItem := range queries {
		if strings.TrimSpace(queryItem.value) == "" {
			continue
		}

		var record userCredentialRecord
		query := fmt.Sprintf(`SELECT user_profile_id, user_name, role, password_hash, hash_algorithm, status, metadata FROM entitiy_users WHERE %s = ? LIMIT 1`, queryItem.column)
		err := s.mysql.Get(ctx, &record, query, queryItem.value)
		if err == nil {
			return &record, nil
		}
		if repo.IsNotFound(err) {
			continue
		}
		return nil, fmt.Errorf("query user credential by %s failed: %w", queryItem.column, err)
	}

	return nil, nil
}

func (s *UserCredentialService) validateUserStatus(status string, metadata []byte) error {
	normalized := strings.ToLower(strings.TrimSpace(status))
	if normalized == "" || normalized == string(commonmodel.UserStatusActive) {
		if s.isRiskRejected(metadata) {
			return &modelsystem.ErrUserRiskRejected
		}
		return nil
	}

	switch normalized {
	case string(commonmodel.UserStatusInactive), "disabled", "disable":
		return &modelsystem.ErrUserDisabled
	case string(commonmodel.UserStatusBanned), "blocked":
		return &modelsystem.ErrUserBanned
	default:
		return &modelsystem.ErrUserDisabled
	}
}

func (s *UserCredentialService) isRiskRejected(metadata []byte) bool {
	_ = s
	if len(metadata) == 0 {
		return false
	}

	var payload map[string]any
	if err := json.Unmarshal(metadata, &payload); err != nil {
		return false
	}

	for _, key := range []string{"risk_status", "auth_control_status", "auth_status", "decision"} {
		value, ok := payload[key]
		if !ok {
			continue
		}
		raw := strings.ToLower(strings.TrimSpace(fmt.Sprint(value)))
		switch raw {
		case "rejected", "reject", "deny", "denied", "blocked":
			return true
		}
	}

	for _, key := range []string{"risk_rejected", "auth_rejected"} {
		value, ok := payload[key]
		if !ok {
			continue
		}
		if rejected, ok := value.(bool); ok && rejected {
			return true
		}
	}

	return false
}

func (s *UserCredentialService) defaultUserScopes(role string) []string {
	_ = s
	if strings.EqualFold(strings.TrimSpace(role), "admin") {
		return []string{"user:read", "user:write", "user:manage"}
	}
	return []string{"user:read"}
}
