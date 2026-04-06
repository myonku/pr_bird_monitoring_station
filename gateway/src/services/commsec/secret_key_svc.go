package commsec

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// NewSecretKeyServiceFromConfig 基于本地密钥配置构建密钥服务。
// 该构造器负责装载并校验本地私钥/公钥，同时保留全局公钥目录查询能力。
func NewSecretKeyServiceFromConfig(
	cfg *modelsystem.SecretKeyConfig,
	catalog []commsecmodel.ServicePublicKeyRecord,
	mysql *repo.MySQLClient,
) (*SecretKeyService, error) {
	normalized := cfg.Normalized("gateway")
	if !normalized.Enabled {
		return NewSecretKeyServiceWithMySQL(
			commsecmodel.ServicePublicKeyRecord{},
			commsecmodel.LocalPrivateKeyRef{},
			catalog,
			mysql,
		), nil
	}

	if normalized.ActiveKeyID == "" {
		return nil, &modelsystem.ErrKeyIDRequired
	}

	publicRef := normalized.PublicKeyRef
	if publicRef == "" {
		publicRef = normalized.ActiveKeyID + ".public.pem"
	}
	privateRef := normalized.PrivateKeyRef
	if privateRef == "" {
		privateRef = normalized.ActiveKeyID + ".private.pem"
	}

	publicPEM, err := loadPEMBytesFromRef(publicRef, normalized.SecretDir)
	if err != nil {
		return nil, err
	}
	privatePEM, err := loadPEMBytesFromRef(privateRef, normalized.SecretDir)
	if err != nil {
		return nil, err
	}

	if err = ensureSPKIPublicKeyPEM(publicPEM); err != nil {
		return nil, err
	}
	detectedSignature, err := detectSignatureAlgorithm(publicPEM)
	if err != nil {
		return nil, err
	}
	if normalized.SignatureAlgorithm != "" && normalized.SignatureAlgorithm != string(detectedSignature) {
		return nil, fmt.Errorf(
			"signature algorithm mismatch: configured=%s detected=%s",
			normalized.SignatureAlgorithm,
			detectedSignature,
		)
	}
	if err = ensurePKCS8PrivateKeyPEM(privatePEM); err != nil {
		return nil, err
	}
	if err = ensurePrivateKeyMatchesAlgorithm(privatePEM, detectedSignature); err != nil {
		return nil, err
	}

	owner := commsecmodel.ServiceKeyOwner{
		OwnerType:    commsecmodel.CommKeyOwnerType(normalized.OwnerType),
		EntityType:   normalized.EntityType,
		EntityID:     normalized.EntityID,
		EntityName:   normalized.EntityName,
		ServiceID:    normalized.ServiceID,
		ServiceName:  normalized.ServiceName,
		InstanceID:   normalized.InstanceID,
		InstanceName: normalized.InstanceName,
	}.Normalized()

	now := time.Now()
	localPublic := commsecmodel.ServicePublicKeyRecord{
		KeyID:                normalized.ActiveKeyID,
		Owner:                owner,
		KeyExchangeAlgorithm: commsecmodel.KeyExchangeAlgorithm(normalized.KeyExchangeAlgorithm),
		SignatureAlgorithm:   detectedSignature,
		PublicKeyPEM:         string(publicPEM),
		Fingerprint:          sha256Hex(publicPEM),
		Status:               commsecmodel.CommKeyActive,
		CreatedAt:            now,
		ActivatedAt:          now,
		ExpiresAt:            time.Time{},
		RevokedAt:            time.Time{},
	}
	localPrivate := commsecmodel.LocalPrivateKeyRef{
		KeyID:                normalized.ActiveKeyID,
		Owner:                owner,
		KeyExchangeAlgorithm: commsecmodel.KeyExchangeAlgorithm(normalized.KeyExchangeAlgorithm),
		SignatureAlgorithm:   detectedSignature,
		PrivateKeyRef:        string(privatePEM),
		LoadedAt:             now,
	}

	return NewSecretKeyServiceWithMySQL(localPublic, localPrivate, catalog, mysql), nil
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

// GetPublicKey 返回启动时装载并校验通过的本地公钥快照。
func (s *SecretKeyService) GetPublicKey(ctx context.Context) (commsecmodel.ServicePublicKeyRecord, error) {
	_ = ctx
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.localPublic.KeyID == "" {
		return commsecmodel.ServicePublicKeyRecord{}, &modelsystem.ErrLocalPublicKeyNotConfigured
	}
	return s.localPublic, nil
}

// GetPrivateKeyRef 返回启动时装载并校验通过的本地私钥引用。
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

func loadPEMBytesFromRef(ref string, baseDir string) ([]byte, error) {
	raw := strings.TrimSpace(ref)
	if raw == "" {
		return nil, &modelsystem.ErrLocalPrivateKeyRefNotConfigured
	}
	if strings.Contains(raw, "-----BEGIN") {
		return []byte(raw), nil
	}
	if strings.HasPrefix(raw, "base64:") {
		encoded := strings.TrimSpace(strings.TrimPrefix(raw, "base64:"))
		if encoded == "" {
			return nil, &modelsystem.ErrInvalidPrivateKeyPEM
		}
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, err
		}
		return decoded, nil
	}

	filePath := raw
	if after, ok := strings.CutPrefix(filePath, "file://"); ok {
		filePath = after
	}
	if !filepath.IsAbs(filePath) && baseDir != "" {
		filePath = filepath.Join(baseDir, filePath)
	}
	return os.ReadFile(filePath)
}

func ensureSPKIPublicKeyPEM(publicPEM []byte) error {
	block, _ := pem.Decode(publicPEM)
	if block == nil {
		return &modelsystem.ErrInvalidPublicKeyPEM
	}
	if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		return err
	}
	return nil
}

func ensurePKCS8PrivateKeyPEM(privatePEM []byte) error {
	block, _ := pem.Decode(privatePEM)
	if block == nil {
		return &modelsystem.ErrInvalidPrivateKeyPEM
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		return err
	}
	return nil
}

func detectSignatureAlgorithm(publicPEM []byte) (commsecmodel.SignatureAlgorithm, error) {
	block, _ := pem.Decode(publicPEM)
	if block == nil {
		return "", &modelsystem.ErrInvalidPublicKeyPEM
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}

	switch pub := parsed.(type) {
	case ed25519.PublicKey:
		return commsecmodel.SignatureEd25519, nil
	case *ecdsa.PublicKey:
		if pub.Curve != nil && pub.Curve.Params().Name != "P-256" {
			return "", &modelsystem.ErrUnsupportedSignatureAlgorithm
		}
		return commsecmodel.SignatureECDSAP256SHA256, nil
	case *rsa.PublicKey:
		return commsecmodel.SignatureRSAPSSSHA256, nil
	default:
		return "", &modelsystem.ErrUnsupportedPublicKeyType
	}
}

func ensurePrivateKeyMatchesAlgorithm(
	privatePEM []byte,
	algorithm commsecmodel.SignatureAlgorithm,
) error {
	block, _ := pem.Decode(privatePEM)
	if block == nil {
		return &modelsystem.ErrInvalidPrivateKeyPEM
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	switch algorithm {
	case commsecmodel.SignatureEd25519:
		if _, ok := parsed.(ed25519.PrivateKey); !ok {
			return &modelsystem.ErrPrivateKeyNotEd25519
		}
		return nil
	case commsecmodel.SignatureECDSAP256SHA256:
		priv, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			return &modelsystem.ErrPrivateKeyNotECDSA
		}
		if priv.Curve != nil && priv.Curve.Params().Name != "P-256" {
			return &modelsystem.ErrUnsupportedSignatureAlgorithm
		}
		return nil
	case commsecmodel.SignatureRSAPSSSHA256:
		if _, ok := parsed.(*rsa.PrivateKey); !ok {
			return &modelsystem.ErrPrivateKeyNotRSA
		}
		return nil
	default:
		return &modelsystem.ErrUnsupportedSignatureAlgorithm
	}
}

func sha256Hex(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
