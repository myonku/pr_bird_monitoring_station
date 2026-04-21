package edge_server_auth_dto

// BootstrapChallenge 是边缘端请求挑战后得到的挑战载荷。
type BootstrapChallenge struct {
	ChallengeID string `json:"challenge_id"`
	Nonce       string `json:"nonce"`
	Issuer      string `json:"issuer"`
	Audience    string `json:"audience"`

	IssuedAtMs  int64 `json:"issued_at_ms"`
	ExpiresAtMs int64 `json:"expires_at_ms"`

	EntityType string `json:"entity_type"`
	EntityID   string `json:"entity_id"`
	KeyID      string `json:"key_id"`
}

// EdgeToken 是边缘端长期凭证中的单个令牌载荷。
type EdgeToken struct {
	Raw         string   `json:"raw"`
	TokenType   string   `json:"token_type"`
	TokenID     string   `json:"token_id"`
	FamilyID    string   `json:"family_id"`
	SessionID   string   `json:"session_id"`
	IssuedAtMs  int64    `json:"issued_at_ms"`
	ExpiresAtMs int64    `json:"expires_at_ms"`
	Scopes      []string `json:"scopes"`
	Role        string   `json:"role"`
}

// EdgeTokenBundle 是边缘端一次认证或刷新后返回的令牌组。
type EdgeTokenBundle struct {
	AccessToken  *EdgeToken `json:"access_token"`
	RefreshToken *EdgeToken `json:"refresh_token"`
}

// EdgeSession 是边缘端会话载荷。
type EdgeSession struct {
	SessionID        string `json:"session_id"`
	PrincipalID      string `json:"principal_id"`
	DeviceID         string `json:"device_id"`
	Status           string `json:"status"`
	IssuedAtMs       int64  `json:"issued_at_ms"`
	ExpiresAtMs      int64  `json:"expires_at_ms"`
	TokenFamilyID    string `json:"token_family_id"`
	LastVerifiedAtMs int64  `json:"last_verified_at_ms"`
}

// EdgeAuthState 是边缘端认证状态的统一返回载荷。
type EdgeAuthState struct {
	Stage         string           `json:"stage"`
	Session       *EdgeSession     `json:"session"`
	Tokens        *EdgeTokenBundle `json:"tokens"`
	FailureReason string           `json:"failure_reason"`
}
