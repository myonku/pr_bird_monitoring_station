package common

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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	iface "certification_server/src/iface/common"
	commsecmodel "certification_server/src/models/commsec"
	modelsystem "certification_server/src/models/system"
	"certification_server/src/repo"
)

var _ iface.IKeyManager = (*SecretKeyService)(nil)

// SecretKeyService 提供通信密钥目录访问能力。
type SecretKeyService struct {
	mu sync.RWMutex

	localPublic  commsecmodel.ServicePublicKeyRecord
	localPrivate commsecmodel.LocalPrivateKeyRef

	mysql *repo.MySQLClient

	catalogByKey map[string]commsecmodel.ServicePublicKeyRecord
}

// NewSecretKeyServiceFromStartupParams 基于启动参数构建密钥服务。
// 该构造器负责装载并校验本地私钥/公钥，同时保留全局公钥目录查询能力。
func NewSecretKeyServiceFromStartupParams(
	params modelsystem.SecretKeyStartupParams,
	catalog []commsecmodel.ServicePublicKeyRecord,
	mysql *repo.MySQLClient,
) (*SecretKeyService, error) {
	if strings.TrimSpace(params.ActiveKeyID) == "" {
		return NewSecretKeyService(
			mysql,
			commsecmodel.ServicePublicKeyRecord{},
			commsecmodel.LocalPrivateKeyRef{},
			catalog,
		), nil
	}

	publicRef := strings.TrimSpace(params.ActiveKeyID) + ".public.pem"
	privateRef := strings.TrimSpace(params.ActiveKeyID) + ".private.pem"

	publicPEM, err := loadPEMBytesFromRef(publicRef, params.SecretKeyDir)
	if err != nil {
		return nil, err
	}
	privatePEM, err := loadPEMBytesFromRef(privateRef, params.SecretKeyDir)
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
	if err = ensurePKCS8PrivateKeyPEM(privatePEM); err != nil {
		return nil, err
	}
	if err = ensurePrivateKeyMatchesAlgorithm(privatePEM, detectedSignature); err != nil {
		return nil, err
	}

	owner := commsecmodel.ServiceKeyOwner{
		EntityType:   params.EntityType,
		EntityID:     params.EntityID,
		EntityName:   params.EntityName,
		InstanceID:   params.InstanceID,
		InstanceName: params.InstanceName,
	}.Normalized()

	now := time.Now()
	localPublic := commsecmodel.ServicePublicKeyRecord{
		KeyID:        strings.TrimSpace(params.ActiveKeyID),
		Owner:        owner,
		PublicKeyPEM: string(publicPEM),
		Fingerprint:  sha256Hex(publicPEM),
		Status:       commsecmodel.CommKeyActive,
		CreatedAt:    now,
		ActivatedAt:  now,
		ExpiresAt:    time.Time{},
		RevokedAt:    time.Time{},
	}
	localPrivate := commsecmodel.LocalPrivateKeyRef{
		KeyID:         strings.TrimSpace(params.ActiveKeyID),
		Owner:         owner,
		PrivateKeyRef: string(privatePEM),
		LoadedAt:      now,
	}

	return NewSecretKeyService(mysql, localPublic, localPrivate, catalog), nil
}

// NewSecretKeyService 创建通信密钥服务实例。
func NewSecretKeyService(
	mysql *repo.MySQLClient,
	localPublic commsecmodel.ServicePublicKeyRecord,
	localPrivate commsecmodel.LocalPrivateKeyRef,
	catalog []commsecmodel.ServicePublicKeyRecord,
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
		mysql:        mysql,
		catalogByKey: m,
	}
}

// GetPublicKey 获取本地服务的公钥信息。
// 返回启动时装载并校验通过的本地公钥快照。
func (s *SecretKeyService) GetPublicKey(ctx context.Context) (commsecmodel.ServicePublicKeyRecord, error) {
	_ = ctx
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.localPublic.KeyID == "" {
		return commsecmodel.ServicePublicKeyRecord{}, &modelsystem.ErrLocalPublicKeyNotConfigured
	}
	return s.localPublic, nil
}

// GetPrivateKeyRef 获取本地服务的私钥引用信息。
// 返回启动时装载并校验通过的本地私钥引用。
func (s *SecretKeyService) GetPrivateKeyRef(ctx context.Context) (commsecmodel.LocalPrivateKeyRef, error) {
	_ = ctx
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.localPrivate.KeyID == "" {
		return commsecmodel.LocalPrivateKeyRef{}, &modelsystem.ErrLocalPrivateKeyRefNotConfigured
	}
	return s.localPrivate, nil
}

// LookupPublicKey 按 key_id/entity_id/owner 统一查询公钥目录。
func (s *SecretKeyService) LookupPublicKey(
	ctx context.Context,
	req *commsecmodel.PublicKeyLookupRequest,
) (commsecmodel.PublicKeyLookupResult, error) {
	if req == nil {
		return commsecmodel.PublicKeyLookupResult{}, &modelsystem.ErrPublicKeyLookupRequestNil
	}
	q := req.Normalized()
	if q.KeyID == "" && q.EntityID == "" && q.Owner == nil {
		return commsecmodel.PublicKeyLookupResult{}, &modelsystem.ErrPublicKeyLookupCriteriaRequired
	}

	if q.KeyID != "" {
		result, err := s.GetPublicKeyByKeyID(ctx, q.KeyID)
		if err != nil {
			return commsecmodel.PublicKeyLookupResult{}, err
		}
		if result.Found && keyMatchesLookup(result.Key, q) {
			result.MatchedBy = "key_id"
			return result, nil
		}
	}

	if q.EntityID != "" {
		result, err := s.GetPublicKeyByEntityID(ctx, q.EntityID)
		if err != nil {
			return commsecmodel.PublicKeyLookupResult{}, err
		}
		if result.Found && keyMatchesLookup(result.Key, q) {
			result.MatchedBy = "entity_id"
			return result, nil
		}
	}

	if q.Owner != nil {
		items, err := s.GetPublicKeysByOwner(ctx, *q.Owner)
		if err != nil {
			return commsecmodel.PublicKeyLookupResult{}, err
		}
		var selected commsecmodel.ServicePublicKeyRecord
		found := false
		for _, item := range items {
			if !keyMatchesLookup(item, q) {
				continue
			}
			if !found {
				selected = item
				found = true
				continue
			}
			if shouldPreferKey(item, selected) {
				selected = item
			}
		}
		if found {
			return commsecmodel.PublicKeyLookupResult{
				Found:     true,
				Key:       selected,
				MatchedBy: "owner",
				CheckedAt: time.Now(),
			}, nil
		}
	}

	return commsecmodel.PublicKeyLookupResult{
		Found:         false,
		FailureReason: "public key not found by lookup criteria",
		CheckedAt:     time.Now(),
	}, nil
}

// GetPublicKeyByKeyID 根据密钥ID查询公钥信息。
func (s *SecretKeyService) GetPublicKeyByKeyID(
	ctx context.Context, keyID string) (commsecmodel.PublicKeyLookupResult, error) {

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

// GetPublicKeyByEntityID 根据实体ID查询公钥信息。
func (s *SecretKeyService) GetPublicKeyByEntityID(
	ctx context.Context, entityID string) (commsecmodel.PublicKeyLookupResult, error) {

	if entityID == "" {
		return commsecmodel.PublicKeyLookupResult{}, &modelsystem.ErrEntityIDRequired
	}

	result := commsecmodel.PublicKeyLookupResult{CheckedAt: time.Now()}

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
		result.Found = false
		result.FailureReason = "entity id not found"
		return result, nil
	}

	result.Found = true
	result.Key = key
	return result, nil
}

// GetPublicKeysByOwner 根据密钥拥有者查询公钥信息列表。
func (s *SecretKeyService) GetPublicKeysByOwner(
	ctx context.Context, owner commsecmodel.ServiceKeyOwner) ([]commsecmodel.ServicePublicKeyRecord, error) {
	owner = owner.Normalized()
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
	ctx context.Context, entityID string) (*commsecmodel.ServicePublicKeyRecord, error) {

	var row struct {
		KeyID        string    `db:"key_id"`
		EntityType   string    `db:"entity_type"`
		EntityID     string    `db:"entity_id"`
		EntityName   string    `db:"entity_name"`
		InstanceID   string    `db:"instance_id"`
		InstanceName string    `db:"instance_name"`
		PublicKeyPEM string    `db:"public_key_pem"`
		Fingerprint  string    `db:"fingerprint"`
		Status       string    `db:"status"`
		CreatedAt    time.Time `db:"created_at"`
		ActivatedAt  time.Time `db:"activated_at"`
		ExpiresAt    time.Time `db:"expires_at"`
	}
	err := s.mysql.Get(ctx, &row, `
SELECT key_id, entity_type, entity_id, entity_name, instance_id, instance_name,
	   public_key_pem, fingerprint,
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

	item := commsecmodel.ServicePublicKeyRecord{
		KeyID: row.KeyID,
		Owner: commsecmodel.ServiceKeyOwner{
			EntityType:   row.EntityType,
			EntityID:     row.EntityID,
			EntityName:   row.EntityName,
			InstanceID:   row.InstanceID,
			InstanceName: row.InstanceName,
		}.Normalized(),
		PublicKeyPEM: row.PublicKeyPEM,
		Fingerprint:  row.Fingerprint,
		Status:       commsecmodel.CommKeyStatus(row.Status),
		CreatedAt:    row.CreatedAt,
		ActivatedAt:  row.ActivatedAt,
		ExpiresAt:    row.ExpiresAt,
	}
	return &item, nil
}

func (s *SecretKeyService) loadPublicKeyByIDFromDB(
	ctx context.Context, keyID string) (*commsecmodel.ServicePublicKeyRecord, error) {

	var row struct {
		KeyID        string    `db:"key_id"`
		EntityType   string    `db:"entity_type"`
		EntityID     string    `db:"entity_id"`
		EntityName   string    `db:"entity_name"`
		InstanceID   string    `db:"instance_id"`
		InstanceName string    `db:"instance_name"`
		PublicKeyPEM string    `db:"public_key_pem"`
		Fingerprint  string    `db:"fingerprint"`
		Status       string    `db:"status"`
		CreatedAt    time.Time `db:"created_at"`
		ActivatedAt  time.Time `db:"activated_at"`
		ExpiresAt    time.Time `db:"expires_at"`
		RevokedAtRaw []byte    `db:"revoked_at"`
	}
	err := s.mysql.Get(ctx, &row, `
SELECT key_id, entity_type, entity_id, entity_name, instance_id, instance_name,
	   public_key_pem, fingerprint,
       status, created_at, activated_at, expires_at, revoked_at
FROM auth_entity_public_keys
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
			EntityType:   row.EntityType,
			EntityID:     row.EntityID,
			EntityName:   row.EntityName,
			InstanceID:   row.InstanceID,
			InstanceName: row.InstanceName,
		}.Normalized(),
		PublicKeyPEM: row.PublicKeyPEM,
		Fingerprint:  row.Fingerprint,
		Status:       commsecmodel.CommKeyStatus(row.Status),
		CreatedAt:    row.CreatedAt,
		ActivatedAt:  row.ActivatedAt,
		ExpiresAt:    row.ExpiresAt,
	}
	return &item, nil
}

func (s *SecretKeyService) loadPublicKeysByOwnerFromDB(
	ctx context.Context, owner commsecmodel.ServiceKeyOwner) ([]commsecmodel.ServicePublicKeyRecord, error) {
	owner = owner.Normalized()

	query := `
SELECT key_id, entity_type, entity_id, entity_name, instance_id, instance_name,
       public_key_pem, fingerprint,
       status, created_at, activated_at, expires_at, revoked_at
FROM auth_entity_public_keys WHERE 1=1`
	args := make([]any, 0)
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
		KeyID        string    `db:"key_id"`
		EntityType   string    `db:"entity_type"`
		EntityID     string    `db:"entity_id"`
		EntityName   string    `db:"entity_name"`
		InstanceID   string    `db:"instance_id"`
		InstanceName string    `db:"instance_name"`
		PublicKeyPEM string    `db:"public_key_pem"`
		Fingerprint  string    `db:"fingerprint"`
		Status       string    `db:"status"`
		CreatedAt    time.Time `db:"created_at"`
		ActivatedAt  time.Time `db:"activated_at"`
		ExpiresAt    time.Time `db:"expires_at"`
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
				EntityType:   r.EntityType,
				EntityID:     r.EntityID,
				EntityName:   r.EntityName,
				InstanceID:   r.InstanceID,
				InstanceName: r.InstanceName,
			}.Normalized(),
			PublicKeyPEM: r.PublicKeyPEM,
			Fingerprint:  r.Fingerprint,
			Status:       commsecmodel.CommKeyStatus(r.Status),
			CreatedAt:    r.CreatedAt,
			ActivatedAt:  r.ActivatedAt,
			ExpiresAt:    r.ExpiresAt,
		})
	}
	return out, nil
}

func matchOwner(expected commsecmodel.ServiceKeyOwner, actual commsecmodel.ServiceKeyOwner) bool {
	expected = expected.Normalized()
	actual = actual.Normalized()
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

func keyMatchesLookup(key commsecmodel.ServicePublicKeyRecord, query commsecmodel.PublicKeyLookupRequest) bool {
	if query.KeyID != "" && key.KeyID != query.KeyID {
		return false
	}
	if query.EntityID != "" && key.Owner.EffectiveEntityID() != query.EntityID {
		return false
	}
	if query.Owner != nil && !matchOwner(*query.Owner, key.Owner) {
		return false
	}
	if query.RequireActive && key.Status != commsecmodel.CommKeyActive {
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
