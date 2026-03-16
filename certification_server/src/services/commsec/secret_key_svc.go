package commsec

import (
	"context"
	"fmt"
	"sync"
	"time"

	interfaces "certification_server/src/interfaces/commsec"
	commsecmodel "certification_server/src/models/commsec"
	"certification_server/src/repo"
)

var _ interfaces.ISecretKeyService = (*SecretKeyService)(nil)

// SecretKeyService 提供通信密钥目录访问能力。
// 当前使用内存模型承载目录与本地私钥引用，后续可替换为数据库与 HSM/KMS。
type SecretKeyService struct {
	mu sync.RWMutex

	localPublic  commsecmodel.ServicePublicKeyRecord
	localPrivate commsecmodel.LocalPrivateKeyRef

	mysql *repo.MySQLClient

	catalogByKey map[string]commsecmodel.ServicePublicKeyRecord
}

func NewSecretKeyService(
	mysql *repo.MySQLClient,
	localPublic commsecmodel.ServicePublicKeyRecord,
	localPrivate commsecmodel.LocalPrivateKeyRef,
	catalog []commsecmodel.ServicePublicKeyRecord,
) *SecretKeyService {
	m := make(map[string]commsecmodel.ServicePublicKeyRecord)
	for _, item := range catalog {
		if item.KeyID != "" {
			m[item.KeyID] = item
		}
	}
	if localPublic.KeyID != "" {
		m[localPublic.KeyID] = localPublic
	}

	return &SecretKeyService{
		localPublic:  localPublic,
		localPrivate: localPrivate,
		mysql:        mysql,
		catalogByKey: m,
	}
}

// GetPublicKey 获取本地服务的公钥信息。
func (s *SecretKeyService) GetPublicKey(ctx context.Context) (commsecmodel.ServicePublicKeyRecord, error) {
	_ = ctx
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.localPublic.KeyID == "" {
		return commsecmodel.ServicePublicKeyRecord{}, fmt.Errorf("local public key is not configured")
	}
	return s.localPublic, nil
}

// GetPrivateKeyRef 获取本地服务的私钥引用信息。
func (s *SecretKeyService) GetPrivateKeyRef(ctx context.Context) (commsecmodel.LocalPrivateKeyRef, error) {
	_ = ctx
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.localPrivate.KeyID == "" {
		return commsecmodel.LocalPrivateKeyRef{}, fmt.Errorf("local private key ref is not configured")
	}
	return s.localPrivate, nil
}

// GetPublicKeyByKeyID 根据密钥ID查询公钥信息。
func (s *SecretKeyService) GetPublicKeyByKeyID(
	ctx context.Context, keyID string) (commsecmodel.PublicKeyLookupResult, error) {

	if keyID == "" {
		return commsecmodel.PublicKeyLookupResult{}, fmt.Errorf("key id is required")
	}

	s.mu.RLock()
	key, ok := s.catalogByKey[keyID]
	s.mu.RUnlock()
	if !ok && s.mysql != nil {
		dbKey, dbErr := s.loadPublicKeyByIDFromDB(ctx, keyID)
		if dbErr == nil && dbKey != nil {
			key = *dbKey
			ok = true
			s.mu.Lock()
			s.catalogByKey[keyID] = key
			s.mu.Unlock()
		}
	}

	result := commsecmodel.PublicKeyLookupResult{CheckedAt: time.Now()}
	if !ok {
		result.Found = false
		result.FailureReason = "key id not found"
		return result, nil
	}

	result.Found = true
	result.Key = key
	return result, nil
}

// GetPublicKeysByOwner 根据密钥拥有者查询公钥信息列表。
func (s *SecretKeyService) GetPublicKeysByOwner(
	ctx context.Context, owner commsecmodel.ServiceKeyOwner) ([]commsecmodel.ServicePublicKeyRecord, error) {
	s.mu.RLock()

	items := make([]commsecmodel.ServicePublicKeyRecord, 0)
	for _, key := range s.catalogByKey {
		if !matchOwner(owner, key.Owner) {
			continue
		}
		items = append(items, key)
	}
	s.mu.RUnlock()

	if len(items) == 0 && s.mysql != nil {
		dbItems, dbErr := s.loadPublicKeysByOwnerFromDB(ctx, owner)
		if dbErr == nil {
			s.mu.Lock()
			for _, item := range dbItems {
				items = append(items, item)
				s.catalogByKey[item.KeyID] = item
			}
			s.mu.Unlock()
		}
	}

	return items, nil
}

func (s *SecretKeyService) loadPublicKeyByIDFromDB(
	ctx context.Context, keyID string) (*commsecmodel.ServicePublicKeyRecord, error) {

	var row struct {
		KeyID                string    `db:"key_id"`
		OwnerType            string    `db:"owner_type"`
		ServiceID            string    `db:"service_id"`
		ServiceName          string    `db:"service_name"`
		InstanceID           string    `db:"instance_id"`
		InstanceName         string    `db:"instance_name"`
		KeyExchangeAlgorithm string    `db:"key_exchange_algorithm"`
		SignatureAlgorithm   string    `db:"signature_algorithm"`
		PublicKeyPEM         string    `db:"public_key_pem"`
		Fingerprint          string    `db:"fingerprint"`
		Status               string    `db:"status"`
		CreatedAt            time.Time `db:"created_at"`
		ActivatedAt          time.Time `db:"activated_at"`
		ExpiresAt            time.Time `db:"expires_at"`
		RevokedAtRaw         []byte    `db:"revoked_at"`
	}
	err := s.mysql.Get(ctx, &row, `
SELECT key_id, owner_type, service_id, service_name, instance_id, instance_name,
       key_exchange_algorithm, signature_algorithm, public_key_pem, fingerprint,
       status, created_at, activated_at, expires_at, revoked_at
FROM auth_service_public_keys
WHERE key_id = ? LIMIT 1
`, keyID)
	if err != nil {
		if repo.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	item := commsecmodel.ServicePublicKeyRecord{
		KeyID: row.KeyID,
		Owner: commsecmodel.ServiceKeyOwner{
			OwnerType:    commsecmodel.CommKeyOwnerType(row.OwnerType),
			ServiceID:    row.ServiceID,
			ServiceName:  row.ServiceName,
			InstanceID:   row.InstanceID,
			InstanceName: row.InstanceName,
		},
		KeyExchangeAlgorithm: commsecmodel.KeyExchangeAlgorithm(row.KeyExchangeAlgorithm),
		SignatureAlgorithm:   commsecmodel.SignatureAlgorithm(row.SignatureAlgorithm),
		PublicKeyPEM:         row.PublicKeyPEM,
		Fingerprint:          row.Fingerprint,
		Status:               commsecmodel.CommKeyStatus(row.Status),
		CreatedAt:            row.CreatedAt,
		ActivatedAt:          row.ActivatedAt,
		ExpiresAt:            row.ExpiresAt,
	}
	return &item, nil
}

func (s *SecretKeyService) loadPublicKeysByOwnerFromDB(
	ctx context.Context, owner commsecmodel.ServiceKeyOwner) ([]commsecmodel.ServicePublicKeyRecord, error) {

	query := `
SELECT key_id, owner_type, service_id, service_name, instance_id, instance_name,
       key_exchange_algorithm, signature_algorithm, public_key_pem, fingerprint,
       status, created_at, activated_at, expires_at, revoked_at
FROM auth_service_public_keys WHERE 1=1`
	args := make([]any, 0)
	if owner.OwnerType != "" {
		query += ` AND owner_type = ?`
		args = append(args, string(owner.OwnerType))
	}
	if owner.ServiceID != "" {
		query += ` AND service_id = ?`
		args = append(args, owner.ServiceID)
	}
	if owner.ServiceName != "" {
		query += ` AND service_name = ?`
		args = append(args, owner.ServiceName)
	}
	if owner.InstanceID != "" {
		query += ` AND instance_id = ?`
		args = append(args, owner.InstanceID)
	}
	if owner.InstanceName != "" {
		query += ` AND instance_name = ?`
		args = append(args, owner.InstanceName)
	}

	type keyRow struct {
		KeyID                string    `db:"key_id"`
		OwnerType            string    `db:"owner_type"`
		ServiceID            string    `db:"service_id"`
		ServiceName          string    `db:"service_name"`
		InstanceID           string    `db:"instance_id"`
		InstanceName         string    `db:"instance_name"`
		KeyExchangeAlgorithm string    `db:"key_exchange_algorithm"`
		SignatureAlgorithm   string    `db:"signature_algorithm"`
		PublicKeyPEM         string    `db:"public_key_pem"`
		Fingerprint          string    `db:"fingerprint"`
		Status               string    `db:"status"`
		CreatedAt            time.Time `db:"created_at"`
		ActivatedAt          time.Time `db:"activated_at"`
		ExpiresAt            time.Time `db:"expires_at"`
	}
	rows := make([]keyRow, 0)
	if err := s.mysql.Select(ctx, &rows, query, args...); err != nil {
		if repo.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]commsecmodel.ServicePublicKeyRecord, 0, len(rows))
	for _, r := range rows {
		if r.KeyID == "" {
			continue
		}
		out = append(out, commsecmodel.ServicePublicKeyRecord{
			KeyID: r.KeyID,
			Owner: commsecmodel.ServiceKeyOwner{
				OwnerType:    commsecmodel.CommKeyOwnerType(r.OwnerType),
				ServiceID:    r.ServiceID,
				ServiceName:  r.ServiceName,
				InstanceID:   r.InstanceID,
				InstanceName: r.InstanceName,
			},
			KeyExchangeAlgorithm: commsecmodel.KeyExchangeAlgorithm(r.KeyExchangeAlgorithm),
			SignatureAlgorithm:   commsecmodel.SignatureAlgorithm(r.SignatureAlgorithm),
			PublicKeyPEM:         r.PublicKeyPEM,
			Fingerprint:          r.Fingerprint,
			Status:               commsecmodel.CommKeyStatus(r.Status),
			CreatedAt:            r.CreatedAt,
			ActivatedAt:          r.ActivatedAt,
			ExpiresAt:            r.ExpiresAt,
		})
	}
	return out, nil
}

func matchOwner(expected commsecmodel.ServiceKeyOwner, actual commsecmodel.ServiceKeyOwner) bool {
	if expected.OwnerType != "" && expected.OwnerType != actual.OwnerType {
		return false
	}
	if expected.ServiceID != "" && expected.ServiceID != actual.ServiceID {
		return false
	}
	if expected.ServiceName != "" && expected.ServiceName != actual.ServiceName {
		return false
	}
	if expected.InstanceID != "" && expected.InstanceID != actual.InstanceID {
		return false
	}
	if expected.InstanceName != "" && expected.InstanceName != actual.InstanceName {
		return false
	}
	return true
}
