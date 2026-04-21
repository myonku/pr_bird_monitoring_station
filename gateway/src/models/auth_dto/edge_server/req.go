package edge_server_auth_dto

// BootstrapChallengeRequest 是边缘端请求挑战载荷的请求体。
type BootstrapChallengeRequest struct {
	DeviceID string `json:"device_id"`
	KeyID    string `json:"key_id"`
	Audience string `json:"audience"`
}

// SignedBootstrapProof 是边缘端在 bootstrap authenticate 中提交的签名证明。
type SignedBootstrapProof struct {
	ChallengeID        string `json:"challenge_id"`
	DeviceID           string `json:"device_id"`
	KeyID              string `json:"key_id"`
	Signature          string `json:"signature"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	SignedAtMs         int64  `json:"signed_at_ms"`
}

// BootstrapAuthenticateRequest 是边缘端 bootstrap authenticate 的请求载荷。
type BootstrapAuthenticateRequest struct {
	Challenge              BootstrapChallenge   `json:"challenge"`
	Signed                 SignedBootstrapProof `json:"signed"`
	Scopes                 []string             `json:"scopes"`
	Role                   string               `json:"role"`
	RequireDownstreamToken bool                 `json:"require_downstream_token"`
}

// RefreshTokenRequest 是边缘端刷新长期凭证的请求载荷。
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
	ClientID     string `json:"client_id"`
	GatewayID    string `json:"gateway_id"`
	SourceIP     string `json:"source_ip"`
	UserAgent    string `json:"user_agent"`
	RequestID    string `json:"request_id"`
	TraceID      string `json:"trace_id"`
}
