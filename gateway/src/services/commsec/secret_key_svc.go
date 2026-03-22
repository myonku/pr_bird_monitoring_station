package commsec

import (
	"context"
	"sync"
	"time"

	commsecif "gateway/src/interfaces/commsec"
	commsecmodel "gateway/src/models/commsec"
	modelsystem "gateway/src/models/system"
	"gateway/src/repo"
)

var _ commsecif.ISecretKeyService = (*SecretKeyService)(nil)

// SecretKeyService 维护网关本地私钥引用和公钥目录缓存。
type SecretKeyService struct {
	mu sync.RWMutex

	localPublic  commsecmodel.ServicePublicKeyRecord
	localPrivate commsecmodel.LocalPrivateKeyRef
	catalogByKey map[string]commsecmodel.ServicePublicKeyRecord
	mysql        *repo.MySQLClient
}

func NewSecretKeyService(
	localPublic commsecmodel.ServicePublicKeyRecord,
	localPrivate commsecmodel.LocalPrivateKeyRef,
	catalog []commsecmodel.ServicePublicKeyRecord,
) *SecretKeyService {
	return NewSecretKeyServiceWithMySQL(localPublic, localPrivate, catalog, nil)
}

func NewSecretKeyServiceWithMySQL(
	localPublic commsecmodel.ServicePublicKeyRecord,
	localPrivate commsecmodel.LocalPrivateKeyRef,
	catalog []commsecmodel.ServicePublicKeyRecord,
	mysql *repo.MySQLClient,
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
		catalogByKey: m,
		mysql:        mysql,
	}
}

func (s *SecretKeyService) GetPublicKey(ctx context.Context) (commsecmodel.ServicePublicKeyRecord, error) {
	_ = ctx
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.localPublic.KeyID == "" {
		return commsecmodel.ServicePublicKeyRecord{}, &modelsystem.ErrLocalPublicKeyNotConfigured
	}
	return s.localPublic, nil
}

func (s *SecretKeyService) GetPrivateKeyRef(ctx context.Context) (commsecmodel.LocalPrivateKeyRef, error) {
	_ = ctx
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.localPrivate.KeyID == "" {
		return commsecmodel.LocalPrivateKeyRef{}, &modelsystem.ErrLocalPrivateKeyRefNotConfigured
	}
	return s.localPrivate, nil
}

func (s *SecretKeyService) GetPublicKeyByKeyID(
	ctx context.Context, keyID string,
) (commsecmodel.PublicKeyLookupResult, error) {
	if keyID == "" {
		return commsecmodel.PublicKeyLookupResult{}, &modelsystem.ErrKeyIDRequired
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
	if !ok {
		return commsecmodel.PublicKeyLookupResult{Found: false, FailureReason: "key id not found"}, nil
	}
	return commsecmodel.PublicKeyLookupResult{Found: true, Key: key}, nil
}

func (s *SecretKeyService) GetPublicKeysByOwner(
	ctx context.Context, owner commsecmodel.ServiceKeyOwner,
) ([]commsecmodel.ServicePublicKeyRecord, error) {
	s.mu.RLock()
	items := make([]commsecmodel.ServicePublicKeyRecord, 0)
	for _, item := range s.catalogByKey {
		if !matchOwner(owner, item.Owner) {
			continue
		}
		items = append(items, item)
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
	ctx context.Context, keyID string,
) (*commsecmodel.ServicePublicKeyRecord, error) {
	if s.mysql == nil {
		return nil, &modelsystem.ErrNilMySQLClient
	}
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
	}
	err := s.mysql.Get(ctx, &row, `
SELECT key_id, owner_type, service_id, service_name, instance_id, instance_name,
       key_exchange_algorithm, signature_algorithm, public_key_pem, fingerprint,
       status, created_at, activated_at, expires_at
FROM auth_service_public_keys
WHERE key_id = ?
LIMIT 1
`, keyID)
	if err != nil {
		if repo.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	out := commsecmodel.ServicePublicKeyRecord{
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
	return &out, nil
}

func (s *SecretKeyService) loadPublicKeysByOwnerFromDB(
	ctx context.Context, owner commsecmodel.ServiceKeyOwner,
) ([]commsecmodel.ServicePublicKeyRecord, error) {
	if s.mysql == nil {
		return nil, &modelsystem.ErrNilMySQLClient
	}
	query := `
SELECT key_id, owner_type, service_id, service_name, instance_id, instance_name,
       key_exchange_algorithm, signature_algorithm, public_key_pem, fingerprint,
       status, created_at, activated_at, expires_at
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
