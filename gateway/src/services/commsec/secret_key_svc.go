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
		item.Owner = item.Owner.Normalized()
		if item.KeyID != "" {
			m[item.KeyID] = item
		}
	}
	localPublic.Owner = localPublic.Owner.Normalized()
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

// TODO: 后续根据实际需求，更新函数内部实现，支持从数据库加载或定期刷新本地公钥信息。
func (s *SecretKeyService) GetPublicKey(ctx context.Context) (commsecmodel.ServicePublicKeyRecord, error) {
	_ = ctx
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.localPublic.KeyID == "" {
		return commsecmodel.ServicePublicKeyRecord{}, &modelsystem.ErrLocalPublicKeyNotConfigured
	}
	return s.localPublic, nil
}

// TODO: 后续根据实际需求，更新函数内部实现，支持从安全存储加载或定期刷新本地私钥引用信息。
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

func (s *SecretKeyService) GetPublicKeyByEntityID(
	ctx context.Context, entityID string,
) (commsecmodel.PublicKeyLookupResult, error) {
	if entityID == "" {
		return commsecmodel.PublicKeyLookupResult{}, &modelsystem.ErrEntityIDRequired
	}

	s.mu.RLock()
	key, ok := pickCatalogKeyByEntityID(s.catalogByKey, entityID)
	s.mu.RUnlock()

	if !ok && s.mysql != nil {
		dbKey, dbErr := s.loadActivePublicKeyByEntityIDFromDB(ctx, entityID)
		if dbErr != nil {
			return commsecmodel.PublicKeyLookupResult{}, dbErr
		}
		if dbKey != nil {
			key = *dbKey
			ok = true
			s.mu.Lock()
			s.catalogByKey[key.KeyID] = key
			s.mu.Unlock()
		}
	}

	if !ok {
		return commsecmodel.PublicKeyLookupResult{Found: false, FailureReason: "entity id not found"}, nil
	}
	return commsecmodel.PublicKeyLookupResult{Found: true, Key: key}, nil
}

func (s *SecretKeyService) GetPublicKeysByOwner(
	ctx context.Context, owner commsecmodel.ServiceKeyOwner,
) ([]commsecmodel.ServicePublicKeyRecord, error) {
	owner = owner.Normalized()
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

func pickCatalogKeyByEntityID(
	catalogByKey map[string]commsecmodel.ServicePublicKeyRecord,
	entityID string,
) (commsecmodel.ServicePublicKeyRecord, bool) {
	var chosen commsecmodel.ServicePublicKeyRecord
	found := false
	for _, key := range catalogByKey {
		if key.Owner.EffectiveEntityID() != entityID {
			continue
		}
		if !found {
			chosen = key
			found = true
			continue
		}
		if shouldPreferKey(key, chosen) {
			chosen = key
		}
	}
	return chosen, found
}

func shouldPreferKey(candidate, current commsecmodel.ServicePublicKeyRecord) bool {
	if candidate.Status == commsecmodel.CommKeyActive && current.Status != commsecmodel.CommKeyActive {
		return true
	}
	if candidate.Status != commsecmodel.CommKeyActive && current.Status == commsecmodel.CommKeyActive {
		return false
	}
	if candidate.ActivatedAt.After(current.ActivatedAt) {
		return true
	}
	if candidate.ExpiresAt.After(current.ExpiresAt) {
		return true
	}
	return false
}

func (s *SecretKeyService) loadActivePublicKeyByEntityIDFromDB(
	ctx context.Context, entityID string,
) (*commsecmodel.ServicePublicKeyRecord, error) {
	if s.mysql == nil {
		return nil, &modelsystem.ErrNilMySQLClient
	}
	var row struct {
		KeyID                string    `db:"key_id"`
		OwnerType            string    `db:"owner_type"`
		EntityType           string    `db:"entity_type"`
		EntityID             string    `db:"entity_id"`
		EntityName           string    `db:"entity_name"`
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
SELECT key_id, owner_type, entity_type, entity_id, entity_name, instance_id, instance_name,
       key_exchange_algorithm, signature_algorithm, public_key_pem, fingerprint,
       status, created_at, activated_at, expires_at
FROM auth_entity_public_keys
WHERE entity_id = ?
ORDER BY (status = 'active') DESC, activated_at DESC, expires_at DESC
LIMIT 1
`, entityID)
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
			EntityType:   row.EntityType,
			EntityID:     row.EntityID,
			EntityName:   row.EntityName,
			ServiceID:    row.EntityID,
			ServiceName:  row.EntityName,
			InstanceID:   row.InstanceID,
			InstanceName: row.InstanceName,
		}.Normalized(),
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

func (s *SecretKeyService) loadPublicKeyByIDFromDB(
	ctx context.Context, keyID string,
) (*commsecmodel.ServicePublicKeyRecord, error) {
	if s.mysql == nil {
		return nil, &modelsystem.ErrNilMySQLClient
	}
	var row struct {
		KeyID                string    `db:"key_id"`
		OwnerType            string    `db:"owner_type"`
		EntityType           string    `db:"entity_type"`
		EntityID             string    `db:"entity_id"`
		EntityName           string    `db:"entity_name"`
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
SELECT key_id, owner_type, entity_type, entity_id, entity_name, instance_id, instance_name,
       key_exchange_algorithm, signature_algorithm, public_key_pem, fingerprint,
       status, created_at, activated_at, expires_at
FROM auth_entity_public_keys
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
			EntityType:   row.EntityType,
			EntityID:     row.EntityID,
			EntityName:   row.EntityName,
			ServiceID:    row.EntityID,
			ServiceName:  row.EntityName,
			InstanceID:   row.InstanceID,
			InstanceName: row.InstanceName,
		}.Normalized(),
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
	owner = owner.Normalized()
	if s.mysql == nil {
		return nil, &modelsystem.ErrNilMySQLClient
	}
	query := `
SELECT key_id, owner_type, entity_type, entity_id, entity_name, instance_id, instance_name,
       key_exchange_algorithm, signature_algorithm, public_key_pem, fingerprint,
       status, created_at, activated_at, expires_at
FROM auth_entity_public_keys WHERE 1=1`
	args := make([]any, 0)
	if owner.OwnerType != "" {
		query += ` AND owner_type = ?`
		args = append(args, string(owner.OwnerType))
	}
	if owner.EntityType != "" {
		query += ` AND entity_type = ?`
		args = append(args, owner.EntityType)
	}
	if owner.EffectiveEntityID() != "" {
		query += ` AND entity_id = ?`
		args = append(args, owner.EffectiveEntityID())
	}
	if owner.EffectiveEntityName() != "" {
		query += ` AND entity_name = ?`
		args = append(args, owner.EffectiveEntityName())
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
		EntityType           string    `db:"entity_type"`
		EntityID             string    `db:"entity_id"`
		EntityName           string    `db:"entity_name"`
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
				EntityType:   r.EntityType,
				EntityID:     r.EntityID,
				EntityName:   r.EntityName,
				ServiceID:    r.EntityID,
				ServiceName:  r.EntityName,
				InstanceID:   r.InstanceID,
				InstanceName: r.InstanceName,
			}.Normalized(),
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
	expected = expected.Normalized()
	actual = actual.Normalized()
	if expected.OwnerType != "" && expected.OwnerType != actual.OwnerType {
		return false
	}
	if expected.EntityType != "" && expected.EntityType != actual.EntityType {
		return false
	}
	if expected.EffectiveEntityID() != "" && expected.EffectiveEntityID() != actual.EffectiveEntityID() {
		return false
	}
	if expected.EffectiveEntityName() != "" && expected.EffectiveEntityName() != actual.EffectiveEntityName() {
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
