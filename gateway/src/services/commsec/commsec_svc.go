package commsec

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	commsecif "gateway/src/interfaces/commsec"
	commsecmodel "gateway/src/models/commsec"
	modelsystem "gateway/src/models/system"
	"gateway/src/repo"
	"gateway/src/utils"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

var _ commsecif.ICommSecurityService = (*CommSecurityService)(nil)

// CommSecurityService 提供网关侧应用层安全通道管理实现。
type CommSecurityService struct {
	mu sync.RWMutex

	handshakes map[uuid.UUID]*commsecmodel.ECDHEHandshakeRecord
	channels   map[uuid.UUID]*commsecmodel.SecureChannelSession

	secretKeySvc commsecif.ISecretKeyService
	crypto       *utils.CryptoUtils
	redis        *repo.RedisClient
}

func NewCommSecurityService(secretKeySvc commsecif.ISecretKeyService, crypto *utils.CryptoUtils, redis ...*repo.RedisClient) *CommSecurityService {
	if crypto == nil {
		crypto = &utils.CryptoUtils{}
	}
	var redisClient *repo.RedisClient
	if len(redis) > 0 {
		redisClient = redis[0]
	}
	return &CommSecurityService{
		handshakes:   make(map[uuid.UUID]*commsecmodel.ECDHEHandshakeRecord),
		channels:     make(map[uuid.UUID]*commsecmodel.SecureChannelSession),
		secretKeySvc: secretKeySvc,
		crypto:       crypto,
		redis:        redisClient,
	}
}

func (s *CommSecurityService) InitHandshake(
	ctx context.Context,
	req *commsecmodel.ECDHEHandshakeInitRequest,
) (*commsecmodel.ECDHEHandshakeInitResult, error) {
	if req == nil {
		return nil, &modelsystem.ErrHandshakeInitRequestNil
	}
	if req.Initiator.ServiceID == "" || req.Responder.ServiceID == "" {
		return nil, &modelsystem.ErrInitiatorResponderServiceRequired
	}

	selectedKeyExchange := pickKeyExchange(req.SupportedKeyExchanges)
	selectedSig := pickSignature(req.SupportedSignatures)
	selectedCipher := pickCipher(req.SupportedCipherSuites)

	ephemeral, err := s.crypto.DeriveRandomSymmetricKey(utils.KeySizeAES128)
	if err != nil {
		return nil, err
	}
	nonce, err := s.crypto.DeriveRandomSymmetricKey(utils.KeySizeAES128)
	if err != nil {
		return nil, err
	}

	ttlSec := req.TTLSec
	if ttlSec <= 0 {
		ttlSec = 120
	}
	now := time.Now()
	record := &commsecmodel.ECDHEHandshakeRecord{
		ID:                          uuid.New(),
		Initiator:                   req.Initiator,
		Responder:                   req.Responder,
		InitiatorKeyID:              req.InitiatorKeyID,
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
		if privateRef, pErr := s.secretKeySvc.GetPrivateKeyRef(ctx); pErr == nil && privateRef.PrivateKeyRef != "" {
			payload := buildHandshakeSignPayload(record)
			sig, signErr := s.crypto.SignByAlgorithm(string(selectedSig), payload, []byte(privateRef.PrivateKeyRef))
			if signErr == nil {
				record.InitiatorSignature = sig
			}
		}
	}

	s.mu.Lock()
	s.handshakes[record.ID] = record
	s.mu.Unlock()
	_ = s.cacheHandshake(ctx, record)

	return &commsecmodel.ECDHEHandshakeInitResult{
		Handshake:           *cloneHandshake(record),
		SelectedKeyExchange: selectedKeyExchange,
		SelectedSignature:   selectedSig,
		SelectedCipherSuite: selectedCipher,
	}, nil
}

func (s *CommSecurityService) CompleteHandshake(
	ctx context.Context,
	req *commsecmodel.ECDHEHandshakeCompleteRequest,
) (*commsecmodel.ECDHEHandshakeCompleteResult, error) {
	if req == nil {
		return nil, &modelsystem.ErrHandshakeCompleteRequestNil
	}

	s.mu.Lock()
	handshake := s.handshakes[req.HandshakeID]
	if handshake == nil {
		s.mu.Unlock()
		return nil, &modelsystem.ErrHandshakeNotFound
	}
	if handshake.Status != commsecmodel.HandshakePending {
		s.mu.Unlock()
		return nil, &modelsystem.ErrHandshakeStateInvalid
	}
	if time.Now().After(handshake.ExpiresAt) {
		handshake.Status = commsecmodel.HandshakeExpired
		s.mu.Unlock()
		return nil, &modelsystem.ErrHandshakeExpired
	}

	handshake.ResponderEphemeralPublicKey = req.ResponderEphemeralPublicKey
	handshake.ResponderSignature = req.ResponderSignature
	handshake.ResponderNonce = req.ResponderNonce
	handshake.Status = commsecmodel.HandshakeEstablished
	handshake.CompletedAt = time.Now()

	derivedKeyRef, err := s.crypto.DeriveSessionKeyByHandshake(
		string(handshake.KeyExchangeAlgorithm),
		string(handshake.CipherSuite),
		handshake.InitiatorEphemeralPublicKey,
		handshake.ResponderEphemeralPublicKey,
		handshake.InitiatorNonce,
		handshake.ResponderNonce,
	)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}

	channel := &commsecmodel.SecureChannelSession{
		ID:            uuid.New(),
		HandshakeID:   handshake.ID,
		Binding:       commsecmodel.SecureChannelBinding{},
		Source:        handshake.Initiator,
		Target:        handshake.Responder,
		LocalKeyID:    handshake.InitiatorKeyID,
		PeerKeyID:     handshake.ResponderKeyID,
		CipherSuite:   handshake.CipherSuite,
		Status:        commsecmodel.SecureChannelActive,
		DerivedKeyRef: derivedKeyRef,
		EstablishedAt: handshake.CompletedAt,
		LastUsedAt:    handshake.CompletedAt,
		ExpiresAt:     handshake.ExpiresAt,
	}
	s.channels[channel.ID] = channel
	s.mu.Unlock()
	_ = s.cacheHandshake(ctx, handshake)
	_ = s.cacheChannel(ctx, channel)

	return &commsecmodel.ECDHEHandshakeCompleteResult{Handshake: *cloneHandshake(handshake), Channel: cloneChannel(channel)}, nil
}

func (s *CommSecurityService) EnsureChannel(
	ctx context.Context,
	req *commsecmodel.SecureChannelEnsureRequest,
) (*commsecmodel.SecureChannelSession, error) {
	if req == nil {
		return nil, &modelsystem.ErrChannelEnsureRequestNil
	}

	if !req.ForceReHandshake {
		channel, err := s.GetChannel(ctx, &req.Query)
		if err == nil {
			if !req.RequireActive || channel.Status == commsecmodel.SecureChannelActive {
				if channel.ExpiresAt.IsZero() || time.Now().Before(channel.ExpiresAt) {
					return channel, nil
				}
			}
		}
	}

	if req.HandshakeInit == nil {
		return nil, &modelsystem.ErrHandshakeInitRequired
	}
	initRes, err := s.InitHandshake(ctx, req.HandshakeInit)
	if err != nil {
		return nil, err
	}
	completeRes, err := s.CompleteHandshake(ctx, &commsecmodel.ECDHEHandshakeCompleteRequest{
		HandshakeID:                 initRes.Handshake.ID,
		ResponderEphemeralPublicKey: initRes.Handshake.InitiatorEphemeralPublicKey,
		ResponderSignature:          initRes.Handshake.InitiatorSignature,
		ResponderNonce:              initRes.Handshake.InitiatorNonce,
	})
	if err != nil {
		return nil, err
	}

	if completeRes.Channel != nil {
		s.mu.Lock()
		completeRes.Channel.Binding = req.Query.Binding
		s.channels[completeRes.Channel.ID] = completeRes.Channel
		s.mu.Unlock()
	}
	return completeRes.Channel, nil
}

func (s *CommSecurityService) UpsertChannel(
	ctx context.Context,
	req *commsecmodel.SecureChannelUpsertRequest,
) (*commsecmodel.SecureChannelSession, error) {
	_ = ctx
	if req == nil {
		return nil, &modelsystem.ErrChannelUpsertRequestNil
	}

	ttlSec := req.TTLSec
	if ttlSec <= 0 {
		ttlSec = 120
	}
	now := time.Now()
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
	_ = s.cacheChannel(ctx, channel)
	return cloneChannel(channel), nil
}

func (s *CommSecurityService) GetChannel(
	ctx context.Context,
	req *commsecmodel.SecureChannelQuery,
) (*commsecmodel.SecureChannelSession, error) {
	_ = ctx
	if req == nil {
		return nil, &modelsystem.ErrChannelQueryNil
	}

	s.mu.RLock()
	if req.ChannelID != uuid.Nil {
		if item := s.channels[req.ChannelID]; item != nil {
			s.mu.RUnlock()
			return cloneChannel(item), nil
		}
	}
	s.mu.RUnlock()

	if req.ChannelID != uuid.Nil {
		cached, cacheErr := s.loadChannelFromCache(ctx, req.ChannelID)
		if cacheErr == nil && cached != nil {
			s.trackChannel(cached)
			return cloneChannel(cached), nil
		}
	}

	s.mu.RLock()
	for _, item := range s.channels {
		if req.SourceServiceID != "" && item.Source.ServiceID != req.SourceServiceID {
			continue
		}
		if req.TargetServiceID != "" && item.Target.ServiceID != req.TargetServiceID {
			continue
		}
		if !matchBinding(req.Binding, item.Binding) {
			continue
		}
		s.mu.RUnlock()
		return cloneChannel(item), nil
	}
	s.mu.RUnlock()
	return nil, &modelsystem.ErrChannelNotFound
}

func (s *CommSecurityService) RevokeChannel(ctx context.Context, req *commsecmodel.SecureChannelRevokeRequest) error {
	_ = ctx
	if req == nil {
		return &modelsystem.ErrChannelRevokeRequestNil
	}

	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if req.ChannelID != uuid.Nil {
		if item := s.channels[req.ChannelID]; item != nil {
			item.Status = commsecmodel.SecureChannelRevoked
			item.RevokedAt = now
			_ = s.cacheChannel(ctx, item)
		}
		return nil
	}

	for _, item := range s.channels {
		if !matchBinding(req.Binding, item.Binding) {
			continue
		}
		item.Status = commsecmodel.SecureChannelRevoked
		item.RevokedAt = now
		_ = s.cacheChannel(ctx, item)
	}
	return nil
}

func (s *CommSecurityService) EncryptForChannel(
	ctx context.Context,
	req *commsecmodel.EncryptForChannelRequest,
) (*commsecmodel.EncryptedPayload, error) {
	if req == nil {
		return nil, &modelsystem.ErrChannelEncryptRequestNil
	}
	channel, err := s.GetChannel(ctx, &commsecmodel.SecureChannelQuery{ChannelID: req.ChannelID})
	if err != nil {
		return nil, err
	}
	if channel.Status != commsecmodel.SecureChannelActive {
		return nil, &modelsystem.ErrChannelNotActive
	}
	if !channel.ExpiresAt.IsZero() && time.Now().After(channel.ExpiresAt) {
		return nil, &modelsystem.ErrChannelExpired
	}

	key, err := decodeKey(channel.DerivedKeyRef)
	if err != nil {
		return nil, err
	}
	aad, err := marshalAdditionalData(req.AdditionalData)
	if err != nil {
		return nil, err
	}
	cipherText, err := s.crypto.EncryptWithCipherSuite(string(channel.CipherSuite), req.Payload, key, aad)
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
	return &commsecmodel.EncryptedPayload{CipherText: cipherText, Meta: meta}, nil
}

func (s *CommSecurityService) DecryptFromChannel(
	ctx context.Context,
	req *commsecmodel.DecryptFromChannelRequest,
) (*commsecmodel.DecryptedPayload, error) {
	if req == nil {
		return nil, &modelsystem.ErrChannelDecryptRequestNil
	}
	channel, err := s.GetChannel(ctx, &commsecmodel.SecureChannelQuery{ChannelID: req.ChannelID})
	if err != nil {
		return nil, err
	}
	if channel.Status != commsecmodel.SecureChannelActive {
		return nil, &modelsystem.ErrChannelNotActive
	}
	if !channel.ExpiresAt.IsZero() && time.Now().After(channel.ExpiresAt) {
		return nil, &modelsystem.ErrChannelExpired
	}
	if req.Meta.Sequence > 0 && req.Meta.Sequence < channel.Sequence {
		return nil, &modelsystem.ErrMessageSequenceStale
	}

	key, err := decodeKey(channel.DerivedKeyRef)
	if err != nil {
		return nil, err
	}
	aad, err := marshalAdditionalData(req.Meta.AdditionalData)
	if err != nil {
		return nil, err
	}
	plain, err := s.crypto.DecryptWithCipherSuite(string(channel.CipherSuite), req.CipherText, key, aad)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	tracked := s.channels[channel.ID]
	if tracked != nil {
		if req.Meta.Sequence > tracked.Sequence {
			tracked.Sequence = req.Meta.Sequence
		}
		tracked.LastUsedAt = time.Now()
		channel = cloneChannel(tracked)
	}
	s.mu.Unlock()
	_ = s.cacheChannel(ctx, channel)

	return &commsecmodel.DecryptedPayload{
		Payload:         plain,
		ChannelID:       channel.ID,
		UpdatedSequence: channel.Sequence,
	}, nil
}

func (s *CommSecurityService) cacheHandshake(ctx context.Context, handshake *commsecmodel.ECDHEHandshakeRecord) error {
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
		return nil, &modelsystem.ErrNilRedisClient
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

func (s *CommSecurityService) trackChannel(channel *commsecmodel.SecureChannelSession) {
	if channel == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.channels[channel.ID] = channel
}

func pickKeyExchange(candidates []commsecmodel.KeyExchangeAlgorithm) commsecmodel.KeyExchangeAlgorithm {
	if len(candidates) == 0 {
		return commsecmodel.KeyExchangeECDHEX25519
	}
	for _, item := range candidates {
		if item == commsecmodel.KeyExchangeECDHEX25519 {
			return item
		}
	}
	return candidates[0]
}

func pickSignature(candidates []commsecmodel.SignatureAlgorithm) commsecmodel.SignatureAlgorithm {
	if len(candidates) == 0 {
		return commsecmodel.SignatureEd25519
	}
	for _, item := range candidates {
		if item == commsecmodel.SignatureEd25519 {
			return item
		}
	}
	return candidates[0]
}

func pickCipher(candidates []commsecmodel.CipherSuite) commsecmodel.CipherSuite {
	if len(candidates) == 0 {
		return commsecmodel.CipherSuiteAES256GCM
	}
	for _, item := range candidates {
		if item == commsecmodel.CipherSuiteAES256GCM {
			return item
		}
	}
	return candidates[0]
}

func cloneHandshake(item *commsecmodel.ECDHEHandshakeRecord) *commsecmodel.ECDHEHandshakeRecord {
	if item == nil {
		return nil
	}
	clone := *item
	return &clone
}

func cloneChannel(item *commsecmodel.SecureChannelSession) *commsecmodel.SecureChannelSession {
	if item == nil {
		return nil
	}
	clone := *item
	return &clone
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

func decodeKey(ref string) ([]byte, error) {
	if ref == "" {
		return nil, &modelsystem.ErrEmptyDerivedKeyRef
	}
	return base64.StdEncoding.DecodeString(ref)
}

func marshalAdditionalData(ad map[string]string) ([]byte, error) {
	if len(ad) == 0 {
		return nil, nil
	}
	keys := make([]string, 0, len(ad))
	for key := range ad {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	ordered := make(map[string]string, len(ad))
	for _, key := range keys {
		ordered[key] = ad[key]
	}
	payload, err := json.Marshal(ordered)
	if err != nil {
		return nil, err
	}
	return payload, nil
}

func buildHandshakeSignPayload(item *commsecmodel.ECDHEHandshakeRecord) []byte {
	parts := []string{
		item.ID.String(),
		item.Initiator.ServiceID,
		item.Responder.ServiceID,
		item.InitiatorKeyID,
		string(item.KeyExchangeAlgorithm),
		string(item.SignatureAlgorithm),
		string(item.CipherSuite),
		item.InitiatorEphemeralPublicKey,
		item.InitiatorNonce,
		item.StartedAt.UTC().Format(time.RFC3339Nano),
		item.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}
	return []byte(strings.Join(parts, "|"))
}
