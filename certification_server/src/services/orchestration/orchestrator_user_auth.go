package orchestration

import (
	"context"
	"strings"
	"time"

	commonif "certification_server/src/iface/common"
	orchestrationif "certification_server/src/iface/orchestration"
	authmodel "certification_server/src/models/auth"
	commonmodel "certification_server/src/models/common"
	modelsystem "certification_server/src/models/system"
)

func (s *AuthRequestOrchestratorService) HandleUserPasswordAuth(
	ctx context.Context, req *orchestrationif.UserPasswordAuthRequest,
) (out *orchestrationif.UserPasswordAuthResult, err error) {
	logAuthRequestObservation("auth.user_password")
	defer func() {
		if err != nil {
			logAuthRequestResult("auth.user_password", false, err.Error())
		} else if out != nil && out.Identity != nil {
			logAuthRequestResult("auth.user_password", true, "token_id="+out.Identity.TokenID.String())
		} else {
			logAuthRequestResult("auth.user_password", true, "")
		}
	}()
	if req == nil {
		return nil, &modelsystem.ErrUserPasswordAuthRequestNil
	}
	if s.userCredential == nil || s.sessionManager == nil || s.tokenManager == nil {
		return nil, &modelsystem.ErrUserCredentialDepsNotReady
	}

	username := strings.TrimSpace(req.Username)
	if username == "" {
		return nil, &modelsystem.ErrUsernameRequired
	}
	if strings.TrimSpace(req.Password) == "" {
		return nil, &modelsystem.ErrPasswordRequired
	}

	credential, err := s.userCredential.ValidateCredentials(
		ctx,
		commonif.UserPwdCredentialRequest{
			Username:    username,
			Password:    req.Password,
			Timestamp:   time.Now().Unix(),
			Fingerprint: strings.TrimSpace(req.UserAgent),
		},
	)
	if err != nil {
		return nil, err
	}
	if credential == nil {
		return nil, &modelsystem.ErrInvalidUserCredentials
	}

	principal := credential.Principal
	if principal.EntityType == "" {
		principal.EntityType = commonmodel.EntityUser
	}
	if strings.TrimSpace(principal.EntityID) == "" {
		principal.EntityID = username
	}
	if strings.TrimSpace(principal.PrincipalID()) == "" {
		return nil, &modelsystem.ErrInvalidUserCredentials
	}

	role := strings.TrimSpace(credential.Role)
	if role == "" {
		role = "user"
	}
	scopes := normalizeUserScopes(req.Scopes, credential.Scopes)

	now := time.Now().UTC()
	session, err := s.sessionManager.CreateSession(
		ctx,
		&commonif.SessionIssueRequest{
			Principal:  principal,
			Role:       role,
			Scopes:     append([]string(nil), scopes...),
			AuthMethod: authmodel.AuthMethodPassword,
			ClientID:   strings.TrimSpace(req.ClientID),
			GatewayID:  strings.TrimSpace(req.GatewayID),
			SourceIP:   strings.TrimSpace(req.SourceIP),
			UserAgent:  strings.TrimSpace(req.UserAgent),
			ExpiresAt:  now.Add(defaultSessionTTL),
		},
	)
	if err != nil {
		return nil, err
	}

	audience := strings.TrimSpace(req.Audience)
	if audience == "" {
		audience = "client"
	}
	sourceService := strings.TrimSpace(req.GatewayID)
	if sourceService == "" {
		sourceService = "gateway"
	}

	tokens, err := s.tokenManager.IssueTokenBundle(
		ctx,
		session,
		&commonif.TokenIssueRequest{
			Principal:     principal,
			SessionID:     session.ID,
			FamilyID:      session.TokenFamilyID,
			Audience:      audience,
			Role:          role,
			Scopes:        append([]string(nil), scopes...),
			AuthMethod:    authmodel.AuthMethodPassword,
			ClientID:      strings.TrimSpace(req.ClientID),
			GatewayID:     strings.TrimSpace(req.GatewayID),
			SourceService: sourceService,
			TargetService: "certification_server",
		},
	)
	if err != nil {
		return nil, err
	}

	issuedAt, expiresAt, tokenID, familyID := resolveBootstrapTokenContext(session, tokens)
	identity := &authmodel.IdentityContext{
		Principal:     principal,
		EntityType:    principal.EntityType,
		EntityID:      principal.EntityID,
		PrincipalID:   principal.PrincipalID(),
		SessionID:     session.ID,
		TokenID:       tokenID,
		TokenFamilyID: familyID,
		TokenType:     authmodel.TokenAccess,
		Role:          role,
		Scopes:        append([]string(nil), scopes...),
		AuthMethod:    authmodel.AuthMethodPassword,
		SourceIP:      strings.TrimSpace(req.SourceIP),
		ClientID:      strings.TrimSpace(req.ClientID),
		GatewayID:     strings.TrimSpace(req.GatewayID),
		SourceService: sourceService,
		TargetService: "certification_server",
		UserAgent:     strings.TrimSpace(req.UserAgent),
		RequestID:     strings.TrimSpace(req.RequestID),
		TraceID:       strings.TrimSpace(req.TraceID),
		IssuedAt:      issuedAt,
		ExpiresAt:     expiresAt,
	}

	out = &orchestrationif.UserPasswordAuthResult{
		Identity:  identity,
		Session:   session,
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
	}
	if tokens != nil {
		out.Tokens = *tokens
	}

	return out, nil
}
