package auth

const (
	HeaderInternalAssertion   = "x-internal-assertion"
	HeaderDownstreamTokenID   = "x-downstream-token-id"
	HeaderDownstreamSessionID = "x-downstream-session-id"
	HeaderDownstreamPrincipal = "x-downstream-principal"
)

// InternalAssertionHeader 表示内部断言头部（类 JWS header）。
type InternalAssertionHeader struct {
	Ver string `json:"ver"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ,omitempty"`
}

// InternalAssertionClaims 表示内部断言负载。
type InternalAssertionClaims struct {
	Ver string `json:"ver"`

	Iss string `json:"iss"`
	Aud string `json:"aud"`
	JTI string `json:"jti"`
	IAT int64  `json:"iat"`
	EXP int64  `json:"exp"`

	PrincipalID string `json:"principal_id,omitempty"`
	EntityType  string `json:"entity_type,omitempty"`
	EntityID    string `json:"entity_id,omitempty"`

	SessionID string `json:"session_id,omitempty"`
	TokenID   string `json:"token_id,omitempty"`

	Scopes    []string `json:"scopes,omitempty"`
	GatewayID string   `json:"gateway_id,omitempty"`

	TraceID   string `json:"trace_id,omitempty"`
	RequestID string `json:"request_id,omitempty"`

	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`

	QueryHash       string `json:"query_hash,omitempty"`
	BodySHA256      string `json:"body_sha256,omitempty"`
	SecureChannelID string `json:"secure_channel_id,omitempty"`
}

// InternalAssertionBuildRequest 表示构建内部断言时的输入。
type InternalAssertionBuildRequest struct {
	TargetService string
	Method        string
	Path          string

	Query map[string]string
	Body  []byte

	Identity *IdentityContext
	Grant    *DownstreamAccessGrant

	TraceID   string
	RequestID string

	SecureChannelID string
	TTLSeconds      int64
}
