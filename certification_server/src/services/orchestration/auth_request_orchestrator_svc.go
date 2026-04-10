package orchestration

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	commonif "certification_server/src/iface/common"
	communicationif "certification_server/src/iface/communication"
	iface "certification_server/src/iface/orchestration"
	authmodel "certification_server/src/models/auth"
	commonmodel "certification_server/src/models/common"
	modelsystem "certification_server/src/models/system"

	"github.com/google/uuid"
)

var _ iface.IAuthRequestOrchestrator = (*AuthRequestOrchestratorService)(nil)

var errAuthRequestOrchestratorNotImplemented = errors.New("auth request orchestrator skeleton not implemented")

// AuthRequestOrchestratorService 是认证中心请求编排的最小实现骨架。
type AuthRequestOrchestratorService struct {
	keyManager     commonif.IKeyManager
	sessionManager commonif.ISessionManager
	tokenManager   commonif.ITokenManager

	mu              sync.RWMutex
	bootstrapByID   map[uuid.UUID]authmodel.ChallengePayload
	defaultAudience string
}

// NewAuthRequestOrchestratorService 创建最小可编译编排服务骨架。
func NewAuthRequestOrchestratorService() *AuthRequestOrchestratorService {
	return NewAuthRequestOrchestratorServiceWithDeps(nil, nil, nil)
}

func NewAuthRequestOrchestratorServiceWithDeps(
	keyManager commonif.IKeyManager,
	sessionManager commonif.ISessionManager,
	tokenManager commonif.ITokenManager,
) *AuthRequestOrchestratorService {
	return &AuthRequestOrchestratorService{
		keyManager:      keyManager,
		sessionManager:  sessionManager,
		tokenManager:    tokenManager,
		bootstrapByID:   make(map[uuid.UUID]authmodel.ChallengePayload),
		defaultAudience: "certification_server",
	}
}

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
	if s.sessionManager == nil || s.tokenManager == nil {
		return nil, &modelsystem.ErrBootstrapDepsNotReady
	}
	if req == nil {
		return nil, &modelsystem.ErrBootstrapAuthRequestNil
	}

	challenge, err := s.resolveChallenge(req)
	if err != nil {
		return nil, err
	}

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

func (s *AuthRequestOrchestratorService) HandleUserPasswordAuth(
	ctx context.Context, req *communicationif.UserPasswordAuthRequest,
) (*communicationif.UserPasswordAuthResult, error) {
	if req == nil {
		return nil, &modelsystem.ErrUserPasswordAuthRequestNil
	}
	return nil, errAuthRequestOrchestratorNotImplemented
}

func (s *AuthRequestOrchestratorService) HandleTokenVerify(
	ctx context.Context, req *commonif.TokenVerifyRequest,
) (*authmodel.TokenVerificationResult, error) {
	if req == nil {
		return nil, &modelsystem.ErrRawTokenRequired
	}
	return nil, errAuthRequestOrchestratorNotImplemented
}

func (s *AuthRequestOrchestratorService) HandleSessionValidate(
	ctx context.Context, req *commonif.SessionValidateRequest,
) (*authmodel.Session, error) {
	if req == nil {
		return nil, &modelsystem.ErrSessionValidateRequestNil
	}
	return nil, errAuthRequestOrchestratorNotImplemented
}

func (s *AuthRequestOrchestratorService) HandleTokenRefresh(
	ctx context.Context, req *commonif.TokenRefreshRequest,
) (*authmodel.TokenBundle, error) {
	if req == nil {
		return nil, &modelsystem.ErrRefreshTokenRequired
	}
	return nil, errAuthRequestOrchestratorNotImplemented
}

func (s *AuthRequestOrchestratorService) HandleTokenRevoke(
	ctx context.Context, req *commonif.TokenRevokeRequest,
) error {
	if req == nil {
		return &modelsystem.ErrTokenRevokeRequestNil
	}
	return errAuthRequestOrchestratorNotImplemented
}

func (s *AuthRequestOrchestratorService) HandleDownstreamGrant(
	ctx context.Context, req *communicationif.DownstreamGrantRequest,
) (*authmodel.DownstreamAccessGrant, error) {
	if req == nil {
		return nil, &modelsystem.ErrDownstreamGrantRequestNil
	}
	return nil, errAuthRequestOrchestratorNotImplemented
}

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
	if ok {
		challenge = stored
	}

	if req.Signed.ChallengeID != uuid.Nil && req.Signed.ChallengeID != challenge.ChallengeID {
		return nil, &modelsystem.ErrChallengeResponseMismatch
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
