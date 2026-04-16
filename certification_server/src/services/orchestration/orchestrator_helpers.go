package orchestration

import (
	"strings"
	"time"

	authmodel "certification_server/src/models/auth"
	commonmodel "certification_server/src/models/common"
	modelsystem "certification_server/src/models/system"

	"github.com/google/uuid"
)

func (s *AuthRequestOrchestratorService) resolveChallenge(
	req *authmodel.BootstrapAuthRequest,
) (*authmodel.ChallengePayload, error) {
	if req == nil {
		return nil, &modelsystem.ErrBootstrapAuthRequestNil
	}

	challenge := req.Challenge
	if challenge.ChallengeID == uuid.Nil {
		return nil, &modelsystem.ErrChallengeNotFound
	}

	s.mu.RLock()
	stored, ok := s.bootstrapByID[challenge.ChallengeID]
	s.mu.RUnlock()
	if !ok {
		return nil, &modelsystem.ErrChallengeNotFound
	}
	challenge = stored

	if req.Signed.ChallengeID != uuid.Nil && req.Signed.ChallengeID != challenge.ChallengeID {
		return nil, &modelsystem.ErrChallengeResponseMismatch
	}
	if time.Now().UTC().After(challenge.ExpiresAt) {
		s.consumeBootstrapChallenge(challenge.ChallengeID)
		return nil, &modelsystem.ErrChallengeExpired
	}
	if strings.TrimSpace(challenge.EntityID) == "" {
		return nil, &modelsystem.ErrEntityIDRequired
	}
	if strings.TrimSpace(challenge.KeyID) == "" {
		return nil, &modelsystem.ErrEntityIDAndKeyIDRequired
	}

	out := challenge
	return &out, nil
}

func (s *AuthRequestOrchestratorService) consumeBootstrapChallenge(challengeID uuid.UUID) {
	if challengeID == uuid.Nil {
		return
	}

	s.mu.Lock()
	delete(s.bootstrapByID, challengeID)
	s.mu.Unlock()
}

func normalizeEntityType(raw commonmodel.EntityType) commonmodel.EntityType {
	resolved := strings.TrimSpace(strings.ToLower(string(raw)))
	switch commonmodel.EntityType(resolved) {
	case commonmodel.EntityUser, commonmodel.EntityDevice, commonmodel.EntityService:
		return commonmodel.EntityType(resolved)
	default:
		return commonmodel.EntityService
	}
}

func normalizeScopes(raw []string) []string {
	if len(raw) == 0 {
		return []string{"service:bootstrap"}
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	if len(out) == 0 {
		return []string{"service:bootstrap"}
	}
	return out
}

func normalizeUserScopes(reqScopes []string, credentialScopes []string) []string {
	if len(credentialScopes) > 0 {
		out := make([]string, 0, len(credentialScopes))
		for _, item := range credentialScopes {
			trimmed := strings.TrimSpace(item)
			if trimmed == "" {
				continue
			}
			out = append(out, trimmed)
		}
		if len(out) > 0 {
			return out
		}
	}

	if len(reqScopes) > 0 {
		out := make([]string, 0, len(reqScopes))
		for _, item := range reqScopes {
			trimmed := strings.TrimSpace(item)
			if trimmed == "" {
				continue
			}
			out = append(out, trimmed)
		}
		if len(out) > 0 {
			return out
		}
	}

	return []string{"user:read"}
}

func resolveBootstrapTokenContext(
	session *authmodel.Session,
	bundle *authmodel.TokenBundle,
) (time.Time, time.Time, uuid.UUID, uuid.UUID) {
	issuedAt := time.Now().UTC()
	expiresAt := issuedAt.Add(15 * time.Minute)
	tokenID := uuid.Nil
	familyID := uuid.Nil

	if session != nil {
		if !session.CreatedAt.IsZero() {
			issuedAt = session.CreatedAt
		}
		if !session.ExpiresAt.IsZero() {
			expiresAt = session.ExpiresAt
		}
		if session.TokenFamilyID != uuid.Nil {
			familyID = session.TokenFamilyID
		}
	}
	if bundle != nil && bundle.AccessToken != nil {
		if !bundle.AccessToken.Claims.IssuedAt.IsZero() {
			issuedAt = bundle.AccessToken.Claims.IssuedAt
		}
		if !bundle.AccessToken.Claims.ExpiresAt.IsZero() {
			expiresAt = bundle.AccessToken.Claims.ExpiresAt
		}
		if bundle.AccessToken.Claims.TokenID != uuid.Nil {
			tokenID = bundle.AccessToken.Claims.TokenID
		}
		if bundle.AccessToken.Claims.FamilyID != uuid.Nil {
			familyID = bundle.AccessToken.Claims.FamilyID
		}
	}

	return issuedAt, expiresAt, tokenID, familyID
}
