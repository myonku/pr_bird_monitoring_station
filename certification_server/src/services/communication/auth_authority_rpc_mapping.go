package communication

import (
	"strings"
	"time"

	authv1 "certification_server/src/gen/auth/v1"
	authmodel "certification_server/src/models/auth"
	commonmodel "certification_server/src/models/common"
)

func toUnixMillis(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.UnixMilli()
}

func mapModelEntityTypeToProto(value commonmodel.EntityType) authv1.EntityType {
	switch strings.TrimSpace(strings.ToLower(string(value))) {
	case string(commonmodel.EntityUser):
		return authv1.EntityType_ENTITY_TYPE_USER
	case string(commonmodel.EntityDevice):
		return authv1.EntityType_ENTITY_TYPE_DEVICE
	case string(commonmodel.EntityService):
		return authv1.EntityType_ENTITY_TYPE_SERVICE
	default:
		return authv1.EntityType_ENTITY_TYPE_UNSPECIFIED
	}
}

func mapModelTokenTypeToProto(value authmodel.TokenType) authv1.TokenType {
	switch strings.TrimSpace(strings.ToLower(string(value))) {
	case string(authmodel.TokenAccess):
		return authv1.TokenType_TOKEN_TYPE_ACCESS
	case string(authmodel.TokenRefresh):
		return authv1.TokenType_TOKEN_TYPE_REFRESH
	case string(authmodel.TokenService):
		return authv1.TokenType_TOKEN_TYPE_SERVICE
	case string(authmodel.TokenDownstream):
		return authv1.TokenType_TOKEN_TYPE_DOWNSTREAM
	default:
		return authv1.TokenType_TOKEN_TYPE_UNSPECIFIED
	}
}

func mapModelTokenStatusToProto(value authmodel.TokenStatus) authv1.TokenStatus {
	switch strings.TrimSpace(strings.ToLower(string(value))) {
	case string(authmodel.TokenStatusActive):
		return authv1.TokenStatus_TOKEN_STATUS_ACTIVE
	case string(authmodel.TokenStatusRotated):
		return authv1.TokenStatus_TOKEN_STATUS_ROTATED
	case string(authmodel.TokenStatusRevoked):
		return authv1.TokenStatus_TOKEN_STATUS_REVOKED
	case string(authmodel.TokenStatusExpired):
		return authv1.TokenStatus_TOKEN_STATUS_EXPIRED
	default:
		return authv1.TokenStatus_TOKEN_STATUS_UNSPECIFIED
	}
}

func mapModelTokenStorageToProto(value authmodel.TokenStorage) authv1.TokenStorage {
	switch strings.TrimSpace(strings.ToLower(string(value))) {
	case string(authmodel.TokenStorageCache):
		return authv1.TokenStorage_TOKEN_STORAGE_CACHE
	case string(authmodel.TokenStorageDatabase):
		return authv1.TokenStorage_TOKEN_STORAGE_DATABASE
	case string(authmodel.TokenStorageHybrid):
		return authv1.TokenStorage_TOKEN_STORAGE_HYBRID
	default:
		return authv1.TokenStorage_TOKEN_STORAGE_UNSPECIFIED
	}
}

func mapModelSessionStatusToProto(value authmodel.SessionStatus) authv1.SessionStatus {
	switch strings.TrimSpace(strings.ToLower(string(value))) {
	case string(authmodel.SessionActive):
		return authv1.SessionStatus_SESSION_STATUS_ACTIVE
	case string(authmodel.SessionRevoked):
		return authv1.SessionStatus_SESSION_STATUS_REVOKED
	case string(authmodel.SessionExpired):
		return authv1.SessionStatus_SESSION_STATUS_EXPIRED
	case string(authmodel.SessionBlocked):
		return authv1.SessionStatus_SESSION_STATUS_BLOCKED
	default:
		return authv1.SessionStatus_SESSION_STATUS_UNSPECIFIED
	}
}

func mapModelAuthMethodToProto(value authmodel.AuthMethod) authv1.AuthMethod {
	switch strings.TrimSpace(strings.ToLower(string(value))) {
	case string(authmodel.AuthMethodPassword):
		return authv1.AuthMethod_AUTH_METHOD_PASSWORD
	case string(authmodel.AuthMethodDeviceSecret):
		return authv1.AuthMethod_AUTH_METHOD_DEVICE_SECRET
	case string(authmodel.AuthMethodServiceSecret):
		return authv1.AuthMethod_AUTH_METHOD_SERVICE_SECRET
	case string(authmodel.AuthMethodRefreshToken):
		return authv1.AuthMethod_AUTH_METHOD_REFRESH_TOKEN
	case string(authmodel.AuthMethodTokenExchange):
		return authv1.AuthMethod_AUTH_METHOD_TOKEN_EXCHANGE
	default:
		return authv1.AuthMethod_AUTH_METHOD_UNSPECIFIED
	}
}

func buildPrincipalProto(principal authmodel.Principal) *authv1.Principal {
	return &authv1.Principal{
		EntityType:  mapModelEntityTypeToProto(principal.EntityType),
		EntityId:    strings.TrimSpace(principal.EntityID),
		PrincipalId: strings.TrimSpace(principal.PrincipalID()),
	}
}

func buildIdentityProto(identity *authmodel.IdentityContext) *authv1.IdentityContext {
	if identity == nil {
		return nil
	}

	return &authv1.IdentityContext{
		Principal:     buildPrincipalProto(identity.Principal),
		SessionId:     identity.SessionID.String(),
		TokenId:       identity.TokenID.String(),
		TokenFamilyId: identity.TokenFamilyID.String(),
		Role:          strings.TrimSpace(identity.Role),
		Scopes:        append([]string(nil), identity.Scopes...),
		AuthMethod:    strings.TrimSpace(string(identity.AuthMethod)),
		SourceIp:      strings.TrimSpace(identity.SourceIP),
		ClientId:      strings.TrimSpace(identity.ClientID),
		GatewayId:     strings.TrimSpace(identity.GatewayID),
		SourceService: strings.TrimSpace(identity.SourceService),
		TargetService: strings.TrimSpace(identity.TargetService),
		RequestId:     strings.TrimSpace(identity.RequestID),
		TraceId:       strings.TrimSpace(identity.TraceID),
		IssuedAtMs:    toUnixMillis(identity.IssuedAt),
		ExpiresAtMs:   toUnixMillis(identity.ExpiresAt),
	}
}

func buildSessionProto(session *authmodel.Session) *authv1.Session {
	if session == nil {
		return nil
	}

	return &authv1.Session{
		SessionId:        session.ID.String(),
		Principal:        buildPrincipalProto(session.Principal),
		EntityType:       mapModelEntityTypeToProto(session.EntityType),
		EntityId:         strings.TrimSpace(session.EntityID),
		PrincipalId:      strings.TrimSpace(session.PrincipalID),
		Status:           mapModelSessionStatusToProto(session.Status),
		AuthMethod:       mapModelAuthMethodToProto(session.AuthMethod),
		CreatedByIp:      strings.TrimSpace(session.CreatedByIP),
		LastSeenIp:       strings.TrimSpace(session.LastSeenIP),
		UserAgent:        strings.TrimSpace(session.UserAgent),
		ClientId:         strings.TrimSpace(session.ClientID),
		GatewayId:        strings.TrimSpace(session.GatewayID),
		ScopeSnapshot:    append([]string(nil), session.ScopeSnapshot...),
		RoleSnapshot:     strings.TrimSpace(session.RoleSnapshot),
		TokenFamilyId:    session.TokenFamilyID.String(),
		CreatedAtMs:      toUnixMillis(session.CreatedAt),
		UpdatedAtMs:      toUnixMillis(session.UpdatedAt),
		LastSeenAtMs:     toUnixMillis(session.LastSeenAt),
		LastVerifiedAtMs: toUnixMillis(session.LastVerifiedAt),
		NextRefreshAtMs:  toUnixMillis(session.NextRefreshAt),
		ExpiresAtMs:      toUnixMillis(session.ExpiresAt),
		RevokedAtMs:      toUnixMillis(session.RevokedAt),
		Version:          session.Version,
	}
}

func buildTokenRecordProto(token *authmodel.TokenRecord) *authv1.TokenRecord {
	if token == nil {
		return nil
	}

	return &authv1.TokenRecord{
		Id:                token.ID.String(),
		FamilyId:          token.FamilyID.String(),
		SessionId:         token.SessionID.String(),
		TokenType:         mapModelTokenTypeToProto(token.Type),
		Status:            mapModelTokenStatusToProto(token.Status),
		Storage:           mapModelTokenStorageToProto(token.Storage),
		Principal:         buildPrincipalProto(token.Principal),
		PrincipalId:       strings.TrimSpace(token.PrincipalID),
		ParentTokenId:     token.ParentTokenID.String(),
		ClientId:          strings.TrimSpace(token.ClientID),
		GatewayId:         strings.TrimSpace(token.GatewayID),
		RoleSnapshot:      strings.TrimSpace(token.RoleSnapshot),
		ScopeSnapshot:     append([]string(nil), token.ScopeSnapshot...),
		IssuedAtMs:        toUnixMillis(token.IssuedAt),
		ExpiresAtMs:       toUnixMillis(token.ExpiresAt),
		LastValidatedAtMs: toUnixMillis(token.LastValidatedAt),
		RevokedAtMs:       toUnixMillis(token.RevokedAt),
	}
}

func buildTokenVerificationProto(
	result *authmodel.TokenVerificationResult,
) *authv1.TokenVerificationResult {
	if result == nil {
		return &authv1.TokenVerificationResult{}
	}

	return &authv1.TokenVerificationResult{
		Valid:                result.Valid,
		Status:               mapModelTokenStatusToProto(result.Status),
		Identity:             buildIdentityProto(result.Identity),
		Token:                buildTokenRecordProto(result.Token),
		RevalidationRequired: result.RevalidationRequired,
		FailureReason:        strings.TrimSpace(result.FailureReason),
	}
}

func buildIssuedTokenProto(token *authmodel.IssuedToken) *authv1.IssuedToken {
	if token == nil {
		return nil
	}

	return &authv1.IssuedToken{
		Raw:       strings.TrimSpace(token.Raw),
		TokenType: mapModelTokenTypeToProto(token.Type),
		TtlSec:    token.TTLSec,
	}
}

func buildTokenBundleProto(bundle authmodel.TokenBundle) *authv1.TokenBundle {
	return &authv1.TokenBundle{
		AccessToken:     buildIssuedTokenProto(bundle.AccessToken),
		RefreshToken:    buildIssuedTokenProto(bundle.RefreshToken),
		DownstreamToken: buildIssuedTokenProto(bundle.DownstreamToken),
	}
}
