package auth

const (
	HeaderDownstreamTokenID   = "x-downstream-token-id"
	HeaderDownstreamSessionID = "x-downstream-session-id"
	HeaderDownstreamPrincipal = "x-downstream-principal"

	HeaderDownstreamSourceService                = "x-downstream-source-service"
	HeaderDownstreamTargetService                = "x-downstream-target-service"
	HeaderDownstreamGrantIssuedAt                = "x-downstream-grant-issued-at"
	HeaderDownstreamGrantExpiresAt               = "x-downstream-grant-expires-at"
	HeaderDownstreamAuthVerifyMode               = "x-downstream-auth-verify-mode"
	DownstreamAuthVerifyModeAuthorityDoubleCheck = "authority-double-check"
)
