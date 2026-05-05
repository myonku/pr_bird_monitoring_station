package orchestration

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	commonif "certification_server/src/iface/common"
	authmodel "certification_server/src/models/auth"
	commsecmodel "certification_server/src/models/commsec"
	modelsystem "certification_server/src/models/system"
	"certification_server/src/utils"

	"github.com/google/uuid"
)

func (s *AuthRequestOrchestratorService) HandleBootstrapChallenge(
	ctx context.Context, req *authmodel.ChallengeRequest,
) (out *authmodel.ChallengePayload, err error) {
	logAuthRequestObservation("auth.bootstrap.challenge")
	defer func() {
		if err != nil {
			logAuthRequestResult("auth.bootstrap.challenge", false, err.Error())
		} else if out != nil {
			logAuthRequestResult("auth.bootstrap.challenge", true, "challenge_id="+out.ChallengeID.String())
		} else {
			logAuthRequestResult("auth.bootstrap.challenge", true, "")
		}
	}()
	_ = ctx
	if req == nil {
		return nil, &modelsystem.ErrChallengeRequestNil
	}

	entityID := strings.TrimSpace(req.EntityID)
	if entityID == "" {
		return nil, &modelsystem.ErrEntityIDRequired
	}

	entityType := normalizeEntityType(req.EntityType)
	keyID := strings.TrimSpace(req.KeyID)
	audience := strings.TrimSpace(req.Audience)
	if audience == "" {
		audience = s.defaultAudience
	}

	ttlSec := req.TTLSec
	if ttlSec <= 0 {
		ttlSec = 60
	}
	// 仅保留毫秒精度以匹配 proto（UnixMilli）的精度契约，
	// 避免网关签名 payload 与认证中心验签 payload 因纳秒差异导致不匹配。
	now := time.Now().UTC().Truncate(time.Millisecond)

	challenge := authmodel.ChallengePayload{
		ChallengeID: uuid.New(),
		Issuer:      "certification_server",
		Audience:    audience,
		EntityType:  entityType,
		EntityID:    entityID,
		KeyID:       keyID,
		Nonce:       uuid.NewString(),
		IssuedAt:    now,
		ExpiresAt:   now.Add(time.Duration(ttlSec) * time.Second),
	}

	s.mu.Lock()
	s.bootstrapByID[challenge.ChallengeID] = challenge
	s.mu.Unlock()

	tmp := challenge
	out = &tmp
	return out, nil
}

func (s *AuthRequestOrchestratorService) HandleBootstrapAuthenticate(
	ctx context.Context, req *authmodel.BootstrapAuthRequest,
) (out *authmodel.BootstrapAuthResult, err error) {
	logAuthRequestObservation("auth.bootstrap.authenticate")
	defer func() {
		if err != nil {
			logAuthRequestResult("auth.bootstrap.authenticate", false, err.Error())
		} else if out != nil && out.Identity != nil {
			logAuthRequestResult("auth.bootstrap.authenticate", true, "token_id="+out.Identity.TokenID.String())
		} else {
			logAuthRequestResult("auth.bootstrap.authenticate", true, "")
		}
	}()
	if s.keyManager == nil || s.sessionManager == nil || s.tokenManager == nil {
		return nil, &modelsystem.ErrBootstrapDepsNotReady
	}
	if req == nil {
		return nil, &modelsystem.ErrBootstrapAuthRequestNil
	}

	challenge, err := s.resolveChallenge(req)
	if err != nil {
		return nil, err
	}
	defer s.consumeBootstrapChallenge(challenge.ChallengeID)

	if challenge.ExpiresAt.Before(time.Now().UTC()) {
		return nil, &modelsystem.ErrChallengeExpired
	}

	keyID := strings.TrimSpace(req.Signed.KeyID)
	if keyID == "" {
		keyID = strings.TrimSpace(challenge.KeyID)
	}

	lookupResult, err := s.lookupBootstrapPublicKey(ctx, challenge, keyID)
	if err != nil {
		return nil, err
	}

	if err := s.verifyBootstrapChallengeSignature(challenge, req.Signed, lookupResult); err != nil {
		return nil, err
	}

	entityType := normalizeEntityType(challenge.EntityType)
	entityID := strings.TrimSpace(challenge.EntityID)
	if entityID == "" {
		return nil, &modelsystem.ErrEntityIDRequired
	}

	principal := authmodel.Principal{EntityType: entityType, EntityID: entityID}
	scopes := normalizeScopes(req.Scopes)
	role := strings.TrimSpace(req.Role)
	if role == "" {
		role = "service"
	}

	now := time.Now().UTC()
	session, err := s.sessionManager.CreateSession(
		ctx,
		&commonif.SessionIssueRequest{
			Principal:  principal,
			Role:       role,
			Scopes:     scopes,
			AuthMethod: authmodel.AuthMethodServiceSecret,
			ExpiresAt:  now.Add(15 * time.Minute),
		},
	)
	if err != nil {
		return nil, err
	}

	audience := strings.TrimSpace(challenge.Audience)
	if audience == "" {
		audience = "internal"
	}

	issueReq := &commonif.TokenIssueRequest{
		Principal:     principal,
		SessionID:     session.ID,
		FamilyID:      session.TokenFamilyID,
		Audience:      audience,
		Role:          role,
		Scopes:        append([]string(nil), scopes...),
		AuthMethod:    authmodel.AuthMethodServiceSecret,
		SourceService: principal.PrincipalID(),
		TargetService: "certification_server",
	}
	tokens, err := s.tokenManager.IssueTokenBundle(ctx, session, issueReq)
	if err != nil {
		return nil, err
	}
	if req.RequireDownstreamToken {
		downstreamReq := *issueReq
		downstreamReq.TokenType = authmodel.TokenDownstream
		downstreamReq.TTLSec = 120
		downstream, issueErr := s.tokenManager.IssueToken(ctx, &downstreamReq)
		if issueErr != nil {
			return nil, issueErr
		}
		tokens.DownstreamToken = downstream
	}

	activeCommKeyID := strings.TrimSpace(keyID)
	if activeCommKeyID == "" {
		activeCommKeyID = strings.TrimSpace(lookupResult.Key.KeyID)
	}
	if activeCommKeyID == "" {
		activeCommKeyID = strings.TrimSpace(lookupResult.Key.Owner.EffectiveEntityID())
	}

	issuedAt, expiresAt, tokenID, familyID := resolveBootstrapTokenContext(session, tokens)
	result := &authmodel.BootstrapAuthResult{
		Stage: authmodel.BootstrapStageReady,
		Identity: &authmodel.IdentityContext{
			Principal:     principal,
			EntityType:    principal.EntityType,
			EntityID:      principal.EntityID,
			PrincipalID:   principal.PrincipalID(),
			SessionID:     session.ID,
			TokenID:       tokenID,
			TokenFamilyID: familyID,
			Role:          role,
			Scopes:        append([]string(nil), scopes...),
			AuthMethod:    authmodel.AuthMethodServiceSecret,
			SourceService: principal.PrincipalID(),
			TargetService: "certification_server",
			IssuedAt:      issuedAt,
			ExpiresAt:     expiresAt,
		},
		Session:         session,
		ActiveCommKeyID: activeCommKeyID,
		IssuedAt:        issuedAt,
		ExpiresAt:       expiresAt,
	}
	if tokens != nil {
		result.Tokens = *tokens
	}

	return result, nil
}

func (s *AuthRequestOrchestratorService) lookupBootstrapPublicKey(
	ctx context.Context,
	challenge *authmodel.ChallengePayload,
	keyID string,
) (commsecmodel.PublicKeyLookupResult, error) {
	if challenge == nil {
		return commsecmodel.PublicKeyLookupResult{}, &modelsystem.ErrChallengeNotFound
	}
	if s.keyManager == nil {
		return commsecmodel.PublicKeyLookupResult{}, &modelsystem.ErrBootstrapDepsNotReady
	}

	lookupResult, err := s.keyManager.LookupPublicKey(ctx, &commsecmodel.PublicKeyLookupRequest{
		KeyID:         strings.TrimSpace(keyID),
		EntityID:      strings.TrimSpace(challenge.EntityID),
		RequireActive: true,
	})
	if err != nil {
		return commsecmodel.PublicKeyLookupResult{}, err
	}
	if !lookupResult.Found || strings.TrimSpace(lookupResult.Key.PublicKeyPEM) == "" {
		if strings.TrimSpace(challenge.EntityID) != "" {
			return commsecmodel.PublicKeyLookupResult{}, &modelsystem.ErrPublicKeyNotFoundForEntityID
		}
		return commsecmodel.PublicKeyLookupResult{}, &modelsystem.ErrPublicKeyNotFoundForKeyID
	}
	if strings.TrimSpace(challenge.EntityID) != "" && strings.TrimSpace(lookupResult.Key.Owner.EffectiveEntityID()) != strings.TrimSpace(challenge.EntityID) {
		return commsecmodel.PublicKeyLookupResult{}, &modelsystem.ErrChallengeResponseMismatch
	}
	if strings.TrimSpace(lookupResult.Key.Owner.EntityType) != strings.ToLower(strings.TrimSpace(string(challenge.EntityType))) {
		return commsecmodel.PublicKeyLookupResult{}, &modelsystem.ErrChallengeResponseMismatch
	}

	return lookupResult, nil
}

func (s *AuthRequestOrchestratorService) verifyBootstrapChallengeSignature(
	challenge *authmodel.ChallengePayload,
	signed authmodel.SignedChallengeResponse,
	lookupResult commsecmodel.PublicKeyLookupResult,
) error {
	if challenge == nil {
		return &modelsystem.ErrChallengeNotFound
	}

	providedKeyID := strings.TrimSpace(signed.KeyID)
	if providedKeyID != "" && strings.TrimSpace(challenge.KeyID) != "" && providedKeyID != strings.TrimSpace(challenge.KeyID) {
		return &modelsystem.ErrChallengeResponseMismatch
	}

	algorithm := strings.TrimSpace(string(signed.SignatureAlgorithm))
	if algorithm == "" {
		return &modelsystem.ErrSignatureAlgorithmRequired
	}

	payload, err := buildBootstrapSignaturePayload(challenge)
	if err != nil {
		return err
	}

	verifyErr := (&utils.CryptoUtils{}).VerifyByAlgorithm(
		algorithm,
		payload,
		strings.TrimSpace(signed.Signature),
		[]byte(lookupResult.Key.PublicKeyPEM),
	)
	if verifyErr != nil {
		if isBootstrapSignatureVerificationFailure(verifyErr) {
			return &modelsystem.ErrChallengeResponseMismatch
		}
		return fmt.Errorf("bootstrap signature verification failed: %w", verifyErr)
	}

	return nil
}

func buildBootstrapSignaturePayload(challenge *authmodel.ChallengePayload) ([]byte, error) {
	if challenge == nil {
		return nil, &modelsystem.ErrChallengeNotFound
	}

	fields := []string{
		strings.TrimSpace(challenge.ChallengeID.String()),
		strings.TrimSpace(challenge.Issuer),
		strings.TrimSpace(challenge.Audience),
		strings.ToLower(strings.TrimSpace(string(challenge.EntityType))),
		strings.TrimSpace(challenge.EntityID),
		strings.TrimSpace(challenge.KeyID),
		strings.TrimSpace(challenge.Nonce),
		challenge.IssuedAt.UTC().Format(time.RFC3339Nano),
		challenge.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}

	return []byte(strings.Join(fields, "|")), nil
}

func isBootstrapSignatureVerificationFailure(err error) bool {
	if err == nil {
		return false
	}

	var sysErr *modelsystem.Error
	if !errors.As(err, &sysErr) {
		return false
	}

	return sysErr.ErrType == modelsystem.CryptoErr && strings.Contains(strings.ToLower(sysErr.Info), "signature verification failed")
}
