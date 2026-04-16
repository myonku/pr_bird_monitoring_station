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
) (*authmodel.ChallengePayload, error) {
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
	if keyID == "" {
		keyID = entityID
	}
	audience := strings.TrimSpace(req.Audience)
	if audience == "" {
		audience = s.defaultAudience
	}

	ttlSec := req.TTLSec
	if ttlSec <= 0 {
		ttlSec = 60
	}
	now := time.Now().UTC()

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

	out := challenge
	return &out, nil
}

func (s *AuthRequestOrchestratorService) HandleBootstrapAuthenticate(
	ctx context.Context, req *authmodel.BootstrapAuthRequest,
) (*authmodel.BootstrapAuthResult, error) {
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
	if keyID == "" {
		return nil, &modelsystem.ErrEntityIDAndKeyIDRequired
	}

	if err := s.verifyBootstrapChallengeSignature(ctx, challenge, req.Signed, keyID); err != nil {
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
		ActiveCommKeyID: keyID,
		IssuedAt:        issuedAt,
		ExpiresAt:       expiresAt,
	}
	if tokens != nil {
		result.Tokens = *tokens
	}

	return result, nil
}

func (s *AuthRequestOrchestratorService) verifyBootstrapChallengeSignature(
	ctx context.Context,
	challenge *authmodel.ChallengePayload,
	signed authmodel.SignedChallengeResponse,
	keyID string,
) error {
	if challenge == nil {
		return &modelsystem.ErrChallengeNotFound
	}
	if s.keyManager == nil {
		return &modelsystem.ErrBootstrapDepsNotReady
	}

	resolvedKeyID := strings.TrimSpace(keyID)
	if resolvedKeyID == "" {
		resolvedKeyID = strings.TrimSpace(challenge.KeyID)
	}
	if resolvedKeyID == "" {
		return &modelsystem.ErrEntityIDAndKeyIDRequired
	}

	providedKeyID := strings.TrimSpace(signed.KeyID)
	if providedKeyID != "" && providedKeyID != strings.TrimSpace(challenge.KeyID) {
		return &modelsystem.ErrChallengeResponseMismatch
	}

	algorithm := strings.TrimSpace(string(signed.SignatureAlgorithm))
	if algorithm == "" {
		return &modelsystem.ErrSignatureAlgorithmRequired
	}

	lookupResult, err := s.keyManager.LookupPublicKey(ctx, &commsecmodel.PublicKeyLookupRequest{
		KeyID:         resolvedKeyID,
		RequireActive: true,
	})
	if err != nil {
		return err
	}
	if !lookupResult.Found || strings.TrimSpace(lookupResult.Key.PublicKeyPEM) == "" {
		return &modelsystem.ErrPublicKeyNotFoundForKeyID
	}
	if strings.TrimSpace(lookupResult.Key.Owner.EffectiveEntityID()) != strings.TrimSpace(challenge.EntityID) {
		return &modelsystem.ErrChallengeResponseMismatch
	}
	if strings.TrimSpace(lookupResult.Key.Owner.EntityType) != strings.ToLower(strings.TrimSpace(string(challenge.EntityType))) {
		return &modelsystem.ErrChallengeResponseMismatch
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
