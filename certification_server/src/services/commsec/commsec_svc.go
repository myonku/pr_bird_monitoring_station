package commsec

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	interfaces "certification_server/src/interfaces/commsec"
	commsecmodel "certification_server/src/models/commsec"
	"certification_server/src/repo"
	"certification_server/src/utils"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

var _ interfaces.ICommSecurityService = (*CommSecurityService)(nil)

// CommSecurityService 提供 ECDHE 握手与安全通道缓存管理。
// 真正的曲线计算与签名校验策略后续可替换为完整实现。
type CommSecurityService struct {
	mu sync.RWMutex

	mysql *repo.MySQLClient
	redis *repo.RedisClient

	handshakes map[uuid.UUID]*commsecmodel.ECDHEHandshakeRecord
	channels   map[uuid.UUID]*commsecmodel.SecureChannelSession

	secretKeySvc interfaces.ISecretKeyService
	crypto       *utils.CryptoUtils
}

// NewCommSecurityService 创建新的 CommSecurityService 实例。
func NewCommSecurityService(
	mysql *repo.MySQLClient, redis *repo.RedisClient,
	secretKeySvc interfaces.ISecretKeyService, crypto *utils.CryptoUtils,
) *CommSecurityService {

	if crypto == nil {
		crypto = &utils.CryptoUtils{}
	}

	return &CommSecurityService{
		mysql:        mysql,
		redis:        redis,
		handshakes:   make(map[uuid.UUID]*commsecmodel.ECDHEHandshakeRecord),
		channels:     make(map[uuid.UUID]*commsecmodel.SecureChannelSession),
		secretKeySvc: secretKeySvc,
		crypto:       crypto,
	}
}

// InitHandshake 根据握手初始化请求创建新的 ECDHE 握手记录。
func (s *CommSecurityService) InitHandshake(
	ctx context.Context, req *commsecmodel.ECDHEHandshakeInitRequest,
) (*commsecmodel.ECDHEHandshakeInitResult, error) {

	if req == nil {
		return nil, fmt.Errorf("handshake init request is nil")
	}
	if req.Initiator.ServiceID == "" || req.Responder.ServiceID == "" {
		return nil, fmt.Errorf("initiator and responder service id are required")
	}

	var initiatorKey *commsecmodel.ServicePublicKeyRecord
	if s.secretKeySvc != nil {
		lookup, err := s.secretKeySvc.GetPublicKeyByKeyID(ctx, req.InitiatorKeyID)
		if err != nil {
			return nil, err
		}
		if !lookup.Found {
			return nil, fmt.Errorf("initiator public key not found")
		}
		initiatorKey = &lookup.Key
	}

	selectedKeyExchange := selectKeyExchange(req.SupportedKeyExchanges, initiatorKey)
	selectedSig := selectSignature(req.SupportedSignatures, initiatorKey)
	selectedCipher := selectCipher(req.SupportedCipherSuites)

	ephemeral, err := s.crypto.DeriveRandomSymmetricKey(utils.KeySizeAES128)
	if err != nil {
		return nil, err
	}
	nonce, err := s.crypto.DeriveRandomSymmetricKey(utils.KeySizeAES128)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	ttlSec := req.TTLSec
	if ttlSec <= 0 {
		ttlSec = 120
	}

	handshake := &commsecmodel.ECDHEHandshakeRecord{
		ID:                          uuid.New(),
		Initiator:                   req.Initiator,
		Responder:                   req.Responder,
		InitiatorKeyID:              req.InitiatorKeyID,
		ResponderKeyID:              "",
		KeyExchangeAlgorithm:        selectedKeyExchange,
		SignatureAlgorithm:          selectedSig,
		CipherSuite:                 selectedCipher,
		InitiatorEphemeralPublicKey: ephemeral,
		InitiatorNonce:              nonce,
		Status:                      commsecmodel.HandshakePending,
		StartedAt:                   now,
		ExpiresAt:                   now.Add(time.Duration(ttlSec) * time.Second),
	}

	if s.secretKeySvc != nil {
		privRef, err := s.secretKeySvc.GetPrivateKeyRef(ctx)
		if err == nil && privRef.PrivateKeyRef != "" {
			signPayload := buildHandshakeSignPayload(handshake)
			signature, signErr := s.crypto.SignByAlgorithm(string(selectedSig), signPayload, []byte(privRef.PrivateKeyRef))
			if signErr == nil {
				handshake.InitiatorSignature = signature
			}
		}
	}

	s.mu.Lock()
	s.handshakes[handshake.ID] = handshake
	s.mu.Unlock()

	_ = s.persistHandshake(ctx, handshake)
	_ = s.cacheHandshake(ctx, handshake)

	return &commsecmodel.ECDHEHandshakeInitResult{
		Handshake:           *cloneHandshake(handshake),
		SelectedKeyExchange: selectedKeyExchange,
		SelectedSignature:   selectedSig,
		SelectedCipherSuite: selectedCipher,
	}, nil
}

// CompleteHandshake 根据握手完成请求更新握手记录并创建安全通道。
func (s *CommSecurityService) CompleteHandshake(
	ctx context.Context, req *commsecmodel.ECDHEHandshakeCompleteRequest,
) (*commsecmodel.ECDHEHandshakeCompleteResult, error) {

	if req == nil {
		return nil, fmt.Errorf("handshake complete request is nil")
	}

	s.mu.Lock()
	handshake := s.handshakes[req.HandshakeID]
	if handshake == nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("handshake not found")
	}
	if handshake.Status != commsecmodel.HandshakePending {
		s.mu.Unlock()
		return nil, fmt.Errorf("handshake state is invalid")
	}
	if time.Now().After(handshake.ExpiresAt) {
		handshake.Status = commsecmodel.HandshakeExpired
		s.mu.Unlock()
		return nil, fmt.Errorf("handshake expired")
	}

	handshake.ResponderEphemeralPublicKey = req.ResponderEphemeralPublicKey
	handshake.ResponderSignature = req.ResponderSignature
	handshake.ResponderNonce = req.ResponderNonce

	if s.secretKeySvc != nil {
		responderKey, keyErr := s.selectResponderPublicKey(ctx, handshake.Responder, handshake.SignatureAlgorithm)
		if keyErr != nil {
			handshake.Status = commsecmodel.HandshakeFailed
			handshake.FailureReason = keyErr.Error()
			s.mu.Unlock()
			_ = s.persistHandshake(ctx, handshake)
			_ = s.cacheHandshake(ctx, handshake)
			return nil, keyErr
		}
		handshake.ResponderKeyID = responderKey.KeyID
		payload := buildHandshakeSignPayload(handshake)
		if verifyErr := s.crypto.VerifyByAlgorithm(
			string(handshake.SignatureAlgorithm), payload, req.ResponderSignature, []byte(responderKey.PublicKeyPEM)); verifyErr != nil {
			handshake.Status = commsecmodel.HandshakeFailed
			handshake.FailureReason = "responder signature invalid"
			s.mu.Unlock()
			_ = s.persistHandshake(ctx, handshake)
			_ = s.cacheHandshake(ctx, handshake)
			return nil, fmt.Errorf("responder signature verification failed: %w", verifyErr)
		}
	}

	handshake.Status = commsecmodel.HandshakeEstablished
	handshake.CompletedAt = time.Now()

	derived, derr := s.crypto.DeriveSessionKeyByHandshake(
		string(handshake.KeyExchangeAlgorithm),
		string(handshake.CipherSuite),
		handshake.InitiatorEphemeralPublicKey,
		handshake.ResponderEphemeralPublicKey,
		handshake.InitiatorNonce,
		handshake.ResponderNonce,
	)
	if derr != nil {
		s.mu.Unlock()
		return nil, derr
	}

	channel := &commsecmodel.SecureChannelSession{
		ID:            uuid.New(),
		HandshakeID:   handshake.ID,
		Source:        handshake.Initiator,
		Target:        handshake.Responder,
		LocalKeyID:    handshake.InitiatorKeyID,
		PeerKeyID:     handshake.ResponderKeyID,
		CipherSuite:   handshake.CipherSuite,
		Status:        commsecmodel.SecureChannelActive,
		DerivedKeyRef: derived,
		EstablishedAt: handshake.CompletedAt,
		LastUsedAt:    handshake.CompletedAt,
		ExpiresAt:     handshake.ExpiresAt,
	}

	s.channels[channel.ID] = channel
	s.mu.Unlock()

	_ = s.persistHandshake(ctx, handshake)
	_ = s.cacheHandshake(ctx, handshake)
	_ = s.persistChannel(ctx, channel)
	_ = s.cacheChannel(ctx, channel)

	return &commsecmodel.ECDHEHandshakeCompleteResult{
		Handshake: *cloneHandshake(handshake),
		Channel:   cloneChannel(channel),
	}, nil
}

// UpsertChannel 根据请求创建或更新安全通道记录。
func (s *CommSecurityService) UpsertChannel(
	ctx context.Context, req *commsecmodel.SecureChannelUpsertRequest,
) (*commsecmodel.SecureChannelSession, error) {

	if req == nil {
		return nil, fmt.Errorf("channel upsert request is nil")
	}

	now := time.Now()
	ttlSec := req.TTLSec
	if ttlSec <= 0 {
		ttlSec = 120
	}

	channel := &commsecmodel.SecureChannelSession{
		ID:            uuid.New(),
		HandshakeID:   req.HandshakeID,
		Binding:       req.Binding,
		Source:        req.Source,
		Target:        req.Target,
		LocalKeyID:    req.LocalKeyID,
		PeerKeyID:     req.PeerKeyID,
		CipherSuite:   req.CipherSuite,
		Status:        commsecmodel.SecureChannelActive,
		DerivedKeyRef: req.DerivedKeyRef,
		EstablishedAt: now,
		LastUsedAt:    now,
		ExpiresAt:     now.Add(time.Duration(ttlSec) * time.Second),
	}

	s.mu.Lock()
	s.channels[channel.ID] = channel
	s.mu.Unlock()

	_ = s.persistChannel(ctx, channel)
	_ = s.cacheChannel(ctx, channel)

	return cloneChannel(channel), nil
}

// GetChannel 根据查询条件获取安全通道记录。
func (s *CommSecurityService) GetChannel(
	ctx context.Context, req *commsecmodel.SecureChannelQuery,
) (*commsecmodel.SecureChannelSession, error) {

	if req == nil {
		return nil, fmt.Errorf("channel query is nil")
	}

	s.mu.RLock()
	if req.ChannelID != uuid.Nil {
		channel := s.channels[req.ChannelID]
		if channel != nil {
			s.mu.RUnlock()
			return cloneChannel(channel), nil
		}
	}
	s.mu.RUnlock()

	if req.ChannelID != uuid.Nil && s.redis != nil {
		cached, cacheErr := s.loadChannelFromCache(ctx, req.ChannelID)
		if cacheErr == nil && cached != nil {
			s.trackChannel(cached)
			return cloneChannel(cached), nil
		}
	}
	if req.ChannelID != uuid.Nil && s.mysql != nil {
		dbChannel, dbErr := s.loadChannelFromDB(ctx, req.ChannelID)
		if dbErr == nil && dbChannel != nil {
			s.trackChannel(dbChannel)
			_ = s.cacheChannel(ctx, dbChannel)
			return cloneChannel(dbChannel), nil
		}
	}

	s.mu.RLock()
	for _, channel := range s.channels {
		if !matchBinding(req.Binding, channel.Binding) {
			continue
		}
		if req.SourceServiceID != "" && channel.Source.ServiceID != req.SourceServiceID {
			continue
		}
		if req.TargetServiceID != "" && channel.Target.ServiceID != req.TargetServiceID {
			continue
		}
		s.mu.RUnlock()
		return cloneChannel(channel), nil
	}
	s.mu.RUnlock()

	if s.mysql != nil {
		dbChannel, dbErr := s.loadChannelByQueryFromDB(ctx, req)
		if dbErr == nil && dbChannel != nil {
			s.trackChannel(dbChannel)
			_ = s.cacheChannel(ctx, dbChannel)
			return cloneChannel(dbChannel), nil
		}
	}

	return nil, fmt.Errorf("channel not found")
}

// RevokeChannel 根据查询条件撤销安全通道记录。
func (s *CommSecurityService) RevokeChannel(
	ctx context.Context, req *commsecmodel.SecureChannelRevokeRequest) error {

	if req == nil {
		return fmt.Errorf("channel revoke request is nil")
	}

	s.mu.Lock()

	if req.ChannelID != uuid.Nil {
		channel := s.channels[req.ChannelID]
		if channel != nil {
			channel.Status = commsecmodel.SecureChannelRevoked
			channel.RevokedAt = time.Now()
			_ = s.persistChannel(ctx, channel)
			_ = s.cacheChannel(ctx, channel)
		}
		s.mu.Unlock()
		_ = s.revokeChannelInDB(ctx, req.ChannelID)
		return nil
	}

	for _, channel := range s.channels {
		if !matchBinding(req.Binding, channel.Binding) {
			continue
		}
		channel.Status = commsecmodel.SecureChannelRevoked
		channel.RevokedAt = time.Now()
		_ = s.persistChannel(ctx, channel)
		_ = s.cacheChannel(ctx, channel)
	}
	s.mu.Unlock()

	if s.mysql != nil {
		_ = s.revokeChannelByBindingInDB(ctx, req.Binding)
	}

	return nil
}

// EncryptByChannel 基于安全通道完成应用层消息加密。
func (s *CommSecurityService) EncryptByChannel(
	ctx context.Context, req *commsecmodel.ChannelEncryptRequest,
) (*commsecmodel.ChannelEncryptResult, error) {
	if req == nil {
		return nil, fmt.Errorf("channel encrypt request is nil")
	}
	channel, err := s.GetChannel(ctx, &commsecmodel.SecureChannelQuery{ChannelID: req.ChannelID})
	if err != nil {
		return nil, err
	}
	if channel.Status != commsecmodel.SecureChannelActive {
		return nil, fmt.Errorf("channel is not active")
	}
	if time.Now().After(channel.ExpiresAt) {
		return nil, fmt.Errorf("channel expired")
	}

	key, err := decodeDerivedKey(channel.DerivedKeyRef)
	if err != nil {
		return nil, err
	}

	aad, err := marshalAAD(req.AdditionalData)
	if err != nil {
		return nil, err
	}
	cipherText, err := s.crypto.EncryptWithCipherSuite(string(channel.CipherSuite), req.PlainText, key, aad)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	tracked := s.channels[channel.ID]
	if tracked != nil {
		tracked.Sequence++
		tracked.LastUsedAt = time.Now()
		channel = cloneChannel(tracked)
	}
	s.mu.Unlock()

	_ = s.persistChannel(ctx, channel)
	_ = s.cacheChannel(ctx, channel)

	meta := commsecmodel.EncryptedMessageMeta{
		ChannelID:      channel.ID,
		HandshakeID:    channel.HandshakeID,
		KeyID:          channel.LocalKeyID,
		CipherSuite:    channel.CipherSuite,
		Sequence:       channel.Sequence,
		AdditionalData: req.AdditionalData,
		IssuedAt:       time.Now(),
	}
	return &commsecmodel.ChannelEncryptResult{CipherText: cipherText, Meta: meta}, nil
}

// DecryptByChannel 基于安全通道完成应用层消息解密。
func (s *CommSecurityService) DecryptByChannel(
	ctx context.Context, req *commsecmodel.ChannelDecryptRequest,
) (string, error) {
	if req == nil {
		return "", fmt.Errorf("channel decrypt request is nil")
	}
	channel, err := s.GetChannel(ctx, &commsecmodel.SecureChannelQuery{ChannelID: req.ChannelID})
	if err != nil {
		return "", err
	}
	if channel.Status != commsecmodel.SecureChannelActive {
		return "", fmt.Errorf("channel is not active")
	}
	if time.Now().After(channel.ExpiresAt) {
		return "", fmt.Errorf("channel expired")
	}

	if req.Sequence > 0 && req.Sequence < channel.Sequence {
		return "", fmt.Errorf("message sequence is stale")
	}

	key, err := decodeDerivedKey(channel.DerivedKeyRef)
	if err != nil {
		return "", err
	}
	aad, err := marshalAAD(req.AdditionalData)
	if err != nil {
		return "", err
	}
	plainText, err := s.crypto.DecryptWithCipherSuite(string(channel.CipherSuite), req.CipherText, key, aad)
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	tracked := s.channels[channel.ID]
	if tracked != nil {
		if req.Sequence > tracked.Sequence {
			tracked.Sequence = req.Sequence
		}
		tracked.LastUsedAt = time.Now()
		channel = cloneChannel(tracked)
	}
	s.mu.Unlock()

	_ = s.persistChannel(ctx, channel)
	_ = s.cacheChannel(ctx, channel)
	return plainText, nil
}

func (s *CommSecurityService) persistHandshake(
	ctx context.Context, handshake *commsecmodel.ECDHEHandshakeRecord) error {

	if s.mysql == nil || handshake == nil {
		return nil
	}
	_, err := s.mysql.Exec(ctx, `
INSERT INTO auth_commsec_handshakes(
  id, initiator_owner_type, initiator_service_id, initiator_service_name, initiator_instance_id, initiator_instance_name,
  responder_owner_type, responder_service_id, responder_service_name, responder_instance_id, responder_instance_name,
  initiator_key_id, responder_key_id, key_exchange_algorithm, signature_algorithm, cipher_suite,
  initiator_ephemeral_public_key, responder_ephemeral_public_key, initiator_nonce, responder_nonce,
  initiator_signature, responder_signature, status, failure_reason, started_at, completed_at, expires_at, updated_at
) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON DUPLICATE KEY UPDATE
  responder_key_id=VALUES(responder_key_id), responder_ephemeral_public_key=VALUES(responder_ephemeral_public_key),
  responder_nonce=VALUES(responder_nonce), responder_signature=VALUES(responder_signature), status=VALUES(status),
  failure_reason=VALUES(failure_reason), completed_at=VALUES(completed_at), updated_at=VALUES(updated_at)
`,
		handshake.ID.String(), string(handshake.Initiator.OwnerType), handshake.Initiator.ServiceID, handshake.Initiator.ServiceName,
		handshake.Initiator.InstanceID, handshake.Initiator.InstanceName,
		string(handshake.Responder.OwnerType), handshake.Responder.ServiceID, handshake.Responder.ServiceName,
		handshake.Responder.InstanceID, handshake.Responder.InstanceName,
		handshake.InitiatorKeyID, handshake.ResponderKeyID, string(handshake.KeyExchangeAlgorithm), string(handshake.SignatureAlgorithm), string(handshake.CipherSuite),
		handshake.InitiatorEphemeralPublicKey, handshake.ResponderEphemeralPublicKey, handshake.InitiatorNonce, handshake.ResponderNonce,
		handshake.InitiatorSignature, handshake.ResponderSignature, string(handshake.Status), handshake.FailureReason,
		handshake.StartedAt, nullableTime(handshake.CompletedAt), handshake.ExpiresAt, time.Now(),
	)
	return err
}

func (s *CommSecurityService) cacheHandshake(
	ctx context.Context, handshake *commsecmodel.ECDHEHandshakeRecord) error {

	if s.redis == nil || handshake == nil {
		return nil
	}
	payload, err := json.Marshal(handshake)
	if err != nil {
		return err
	}
	ttl := time.Until(handshake.ExpiresAt)
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return s.redis.Set(ctx, "auth:commsec:handshake:id:"+handshake.ID.String(), payload, ttl)
}

func (s *CommSecurityService) persistChannel(
	ctx context.Context, channel *commsecmodel.SecureChannelSession) error {

	if s.mysql == nil || channel == nil {
		return nil
	}
	_, err := s.mysql.Exec(ctx, `
INSERT INTO auth_secure_channels(
  id, handshake_id, binding_type, binding_session_id, binding_token_id, binding_family_id,
  source_owner_type, source_service_id, source_service_name, source_instance_id, source_instance_name,
  target_owner_type, target_service_id, target_service_name, target_instance_id, target_instance_name,
  local_key_id, peer_key_id, cipher_suite, status, derived_key_ref, seq_no,
	established_at, last_used_at, expires_at, revoked_at, updated_at
) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON DUPLICATE KEY UPDATE
  status=VALUES(status), derived_key_ref=VALUES(derived_key_ref), seq_no=VALUES(seq_no),
	last_used_at=VALUES(last_used_at), expires_at=VALUES(expires_at), revoked_at=VALUES(revoked_at),
	updated_at=VALUES(updated_at)
`,
		channel.ID.String(), channel.HandshakeID.String(), string(channel.Binding.BindingType), nullableUUID(channel.Binding.SessionID), nullableUUID(channel.Binding.TokenID), nullableUUID(channel.Binding.TokenFamilyID),
		string(channel.Source.OwnerType), channel.Source.ServiceID, channel.Source.ServiceName, channel.Source.InstanceID, channel.Source.InstanceName,
		string(channel.Target.OwnerType), channel.Target.ServiceID, channel.Target.ServiceName, channel.Target.InstanceID, channel.Target.InstanceName,
		channel.LocalKeyID, channel.PeerKeyID, string(channel.CipherSuite), string(channel.Status), channel.DerivedKeyRef, channel.Sequence,
		channel.EstablishedAt, channel.LastUsedAt, channel.ExpiresAt, nullableTime(channel.RevokedAt), time.Now(),
	)
	return err
}

func (s *CommSecurityService) cacheChannel(ctx context.Context, channel *commsecmodel.SecureChannelSession) error {
	if s.redis == nil || channel == nil {
		return nil
	}
	payload, err := json.Marshal(channel)
	if err != nil {
		return err
	}
	ttl := time.Until(channel.ExpiresAt)
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return s.redis.Set(ctx, "auth:commsec:channel:id:"+channel.ID.String(), payload, ttl)
}

func (s *CommSecurityService) loadChannelFromCache(ctx context.Context, id uuid.UUID) (*commsecmodel.SecureChannelSession, error) {
	if s.redis == nil {
		return nil, fmt.Errorf("redis not configured")
	}
	raw, err := s.redis.Get(ctx, "auth:commsec:channel:id:"+id.String())
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}
	var channel commsecmodel.SecureChannelSession
	if err := json.Unmarshal([]byte(raw), &channel); err != nil {
		return nil, err
	}
	return &channel, nil
}

func (s *CommSecurityService) loadChannelFromDB(
	ctx context.Context, id uuid.UUID) (*commsecmodel.SecureChannelSession, error) {

	if s.mysql == nil {
		return nil, fmt.Errorf("mysql not configured")
	}
	var row commsecmodel.ChannelRow
	err := s.mysql.Get(ctx, &row, `
SELECT id, handshake_id, binding_type, binding_session_id, binding_token_id, binding_family_id,
       source_owner_type, source_service_id, source_service_name, source_instance_id, source_instance_name,
       target_owner_type, target_service_id, target_service_name, target_instance_id, target_instance_name,
       local_key_id, peer_key_id, cipher_suite, status, derived_key_ref, seq_no,
       established_at, last_used_at, expires_at, revoked_at
FROM auth_secure_channels
WHERE id = ?
LIMIT 1
`, id.String())
	if err != nil {
		if repo.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return mapChannelRow(row)
}

func (s *CommSecurityService) loadChannelByQueryFromDB(
	ctx context.Context, req *commsecmodel.SecureChannelQuery) (*commsecmodel.SecureChannelSession, error) {

	if s.mysql == nil {
		return nil, fmt.Errorf("mysql not configured")
	}
	query := `
SELECT id, handshake_id, binding_type, binding_session_id, binding_token_id, binding_family_id,
       source_owner_type, source_service_id, source_service_name, source_instance_id, source_instance_name,
       target_owner_type, target_service_id, target_service_name, target_instance_id, target_instance_name,
       local_key_id, peer_key_id, cipher_suite, status, derived_key_ref, seq_no,
       established_at, last_used_at, expires_at, revoked_at
FROM auth_secure_channels WHERE 1=1`
	args := make([]any, 0)
	if req.Binding.BindingType != "" {
		query += " AND binding_type = ?"
		args = append(args, string(req.Binding.BindingType))
	}
	if req.Binding.SessionID != uuid.Nil {
		query += " AND binding_session_id = ?"
		args = append(args, req.Binding.SessionID.String())
	}
	if req.Binding.TokenID != uuid.Nil {
		query += " AND binding_token_id = ?"
		args = append(args, req.Binding.TokenID.String())
	}
	if req.Binding.TokenFamilyID != uuid.Nil {
		query += " AND binding_family_id = ?"
		args = append(args, req.Binding.TokenFamilyID.String())
	}
	if req.SourceServiceID != "" {
		query += " AND source_service_id = ?"
		args = append(args, req.SourceServiceID)
	}
	if req.TargetServiceID != "" {
		query += " AND target_service_id = ?"
		args = append(args, req.TargetServiceID)
	}
	query += " ORDER BY updated_at DESC LIMIT 1"

	var row commsecmodel.ChannelRow
	err := s.mysql.Get(ctx, &row, query, args...)
	if err != nil {
		if repo.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return mapChannelRow(row)
}

func (s *CommSecurityService) revokeChannelInDB(ctx context.Context, id uuid.UUID) error {
	if s.mysql == nil || id == uuid.Nil {
		return nil
	}
	_, err := s.mysql.Exec(ctx, `UPDATE auth_secure_channels SET status=?, revoked_at=?, updated_at=? WHERE id=?`,
		string(commsecmodel.SecureChannelRevoked), time.Now(), time.Now(), id.String())
	return err
}

func (s *CommSecurityService) revokeChannelByBindingInDB(
	ctx context.Context, binding commsecmodel.SecureChannelBinding) error {

	if s.mysql == nil {
		return nil
	}
	query := "UPDATE auth_secure_channels SET status=?, revoked_at=?, updated_at=? WHERE 1=1"
	args := []any{string(commsecmodel.SecureChannelRevoked), time.Now(), time.Now()}
	if binding.BindingType != "" {
		query += " AND binding_type=?"
		args = append(args, string(binding.BindingType))
	}
	if binding.SessionID != uuid.Nil {
		query += " AND binding_session_id=?"
		args = append(args, binding.SessionID.String())
	}
	if binding.TokenID != uuid.Nil {
		query += " AND binding_token_id=?"
		args = append(args, binding.TokenID.String())
	}
	if binding.TokenFamilyID != uuid.Nil {
		query += " AND binding_family_id=?"
		args = append(args, binding.TokenFamilyID.String())
	}
	_, err := s.mysql.Exec(ctx, query, args...)
	return err
}

func (s *CommSecurityService) trackChannel(channel *commsecmodel.SecureChannelSession) {
	if channel == nil {
		return
	}
	s.mu.Lock()
	s.channels[channel.ID] = channel
	s.mu.Unlock()
}

func mapChannelRow(row commsecmodel.ChannelRow) (*commsecmodel.SecureChannelSession, error) {
	id, err := uuid.Parse(row.ID)
	if err != nil {
		return nil, err
	}
	handshakeID, _ := uuid.Parse(row.HandshakeID)
	sessionID, _ := uuid.Parse(row.BindingSessionID.String)
	tokenID, _ := uuid.Parse(row.BindingTokenID.String)
	familyID, _ := uuid.Parse(row.BindingFamilyID.String)
	return &commsecmodel.SecureChannelSession{
		ID:          id,
		HandshakeID: handshakeID,
		Binding: commsecmodel.SecureChannelBinding{
			BindingType:   commsecmodel.ChannelBindingType(row.BindingType),
			SessionID:     sessionID,
			TokenID:       tokenID,
			TokenFamilyID: familyID,
		},
		Source: commsecmodel.ServiceKeyOwner{
			OwnerType:    commsecmodel.CommKeyOwnerType(row.SourceOwnerType),
			ServiceID:    row.SourceServiceID,
			ServiceName:  row.SourceServiceName,
			InstanceID:   row.SourceInstanceID,
			InstanceName: row.SourceInstanceName,
		},
		Target: commsecmodel.ServiceKeyOwner{
			OwnerType:    commsecmodel.CommKeyOwnerType(row.TargetOwnerType),
			ServiceID:    row.TargetServiceID,
			ServiceName:  row.TargetServiceName,
			InstanceID:   row.TargetInstanceID,
			InstanceName: row.TargetInstanceName,
		},
		LocalKeyID:    row.LocalKeyID,
		PeerKeyID:     row.PeerKeyID,
		CipherSuite:   commsecmodel.CipherSuite(row.CipherSuite),
		Status:        commsecmodel.SecureChannelStatus(row.Status),
		DerivedKeyRef: row.DerivedKeyRef,
		Sequence:      row.Sequence,
		EstablishedAt: row.EstablishedAt,
		LastUsedAt:    row.LastUsedAt,
		ExpiresAt:     row.ExpiresAt,
		RevokedAt:     row.RevokedAt.Time,
	}, nil
}

func selectKeyExchange(supported []commsecmodel.KeyExchangeAlgorithm, key *commsecmodel.ServicePublicKeyRecord) commsecmodel.KeyExchangeAlgorithm {
	if key != nil && key.KeyExchangeAlgorithm != "" && containsKeyExchange(supported, key.KeyExchangeAlgorithm) {
		return key.KeyExchangeAlgorithm
	}
	if containsKeyExchange(supported, commsecmodel.KeyExchangeECDHEX25519) {
		return commsecmodel.KeyExchangeECDHEX25519
	}
	if containsKeyExchange(supported, commsecmodel.KeyExchangeECDHEP256) {
		return commsecmodel.KeyExchangeECDHEP256
	}
	if containsKeyExchange(supported, commsecmodel.KeyExchangeECDHEP384) {
		return commsecmodel.KeyExchangeECDHEP384
	}
	if len(supported) > 0 {
		return supported[0]
	}
	return commsecmodel.KeyExchangeECDHEX25519
}

func selectSignature(supported []commsecmodel.SignatureAlgorithm, key *commsecmodel.ServicePublicKeyRecord) commsecmodel.SignatureAlgorithm {
	if key != nil && key.SignatureAlgorithm != "" && containsSignature(supported, key.SignatureAlgorithm) {
		return key.SignatureAlgorithm
	}
	if containsSignature(supported, commsecmodel.SignatureEd25519) {
		return commsecmodel.SignatureEd25519
	}
	if containsSignature(supported, commsecmodel.SignatureECDSAP256SHA256) {
		return commsecmodel.SignatureECDSAP256SHA256
	}
	if containsSignature(supported, commsecmodel.SignatureRSAPSSSHA256) {
		return commsecmodel.SignatureRSAPSSSHA256
	}
	if len(supported) > 0 {
		return supported[0]
	}
	return commsecmodel.SignatureEd25519
}

func selectCipher(supported []commsecmodel.CipherSuite) commsecmodel.CipherSuite {
	if containsCipher(supported, commsecmodel.CipherSuiteAES256GCM) {
		return commsecmodel.CipherSuiteAES256GCM
	}
	if containsCipher(supported, commsecmodel.CipherSuiteChaCha20Poly1305) {
		return commsecmodel.CipherSuiteChaCha20Poly1305
	}
	if containsCipher(supported, commsecmodel.CipherSuiteAES128GCM) {
		return commsecmodel.CipherSuiteAES128GCM
	}
	if len(supported) > 0 {
		return supported[0]
	}
	return commsecmodel.CipherSuiteAES256GCM
}

func containsKeyExchange(set []commsecmodel.KeyExchangeAlgorithm, item commsecmodel.KeyExchangeAlgorithm) bool {
	for _, v := range set {
		if v == item {
			return true
		}
	}
	return false
}

func containsSignature(set []commsecmodel.SignatureAlgorithm, item commsecmodel.SignatureAlgorithm) bool {
	for _, v := range set {
		if v == item {
			return true
		}
	}
	return false
}

func containsCipher(set []commsecmodel.CipherSuite, item commsecmodel.CipherSuite) bool {
	for _, v := range set {
		if v == item {
			return true
		}
	}
	return false
}

func (s *CommSecurityService) selectResponderPublicKey(
	ctx context.Context,
	owner commsecmodel.ServiceKeyOwner,
	sig commsecmodel.SignatureAlgorithm,
) (*commsecmodel.ServicePublicKeyRecord, error) {
	if s.secretKeySvc == nil {
		return nil, fmt.Errorf("secret key service is not configured")
	}
	keys, err := s.secretKeySvc.GetPublicKeysByOwner(ctx, owner)
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		if key.Status != commsecmodel.CommKeyActive {
			continue
		}
		if key.SignatureAlgorithm != "" && key.SignatureAlgorithm != sig {
			continue
		}
		return &key, nil
	}
	return nil, fmt.Errorf("no responder key matched signature algorithm")
}

func buildHandshakeSignPayload(h *commsecmodel.ECDHEHandshakeRecord) []byte {
	if h == nil {
		return []byte("")
	}
	parts := []string{
		h.ID.String(),
		string(h.KeyExchangeAlgorithm),
		string(h.SignatureAlgorithm),
		string(h.CipherSuite),
		h.Initiator.ServiceID,
		h.Responder.ServiceID,
		h.InitiatorKeyID,
		h.ResponderKeyID,
		h.InitiatorEphemeralPublicKey,
		h.ResponderEphemeralPublicKey,
		h.InitiatorNonce,
		h.ResponderNonce,
	}
	return []byte(strings.Join(parts, "|"))
}

func decodeDerivedKey(ref string) ([]byte, error) {
	if ref == "" {
		return nil, fmt.Errorf("empty derived key ref")
	}
	return base64.StdEncoding.DecodeString(ref)
}

func marshalAAD(input map[string]string) ([]byte, error) {
	if len(input) == 0 {
		return nil, nil
	}
	keys := make([]string, 0, len(input))
	for k := range input {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	stable := make(map[string]string, len(input))
	for _, k := range keys {
		stable[k] = input[k]
	}
	return json.Marshal(stable)
}

func matchBinding(expected commsecmodel.SecureChannelBinding, actual commsecmodel.SecureChannelBinding) bool {
	if expected.BindingType != "" && expected.BindingType != actual.BindingType {
		return false
	}
	if expected.SessionID != uuid.Nil && expected.SessionID != actual.SessionID {
		return false
	}
	if expected.TokenID != uuid.Nil && expected.TokenID != actual.TokenID {
		return false
	}
	if expected.TokenFamilyID != uuid.Nil && expected.TokenFamilyID != actual.TokenFamilyID {
		return false
	}
	return true
}

func cloneHandshake(h *commsecmodel.ECDHEHandshakeRecord) *commsecmodel.ECDHEHandshakeRecord {
	if h == nil {
		return nil
	}
	out := *h
	return &out
}

func cloneChannel(c *commsecmodel.SecureChannelSession) *commsecmodel.SecureChannelSession {
	if c == nil {
		return nil
	}
	out := *c
	return &out
}

func nullableUUID(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id.String()
}

func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}
