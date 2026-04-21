package appclient_auth_dto

// ClientAuthCredentialsResponse 是客户端认证接口的统一凭证返回载荷。
type ClientAuthCredentialsResponse struct {
	AccessToken        string   `json:"access_token"`
	RefreshToken       string   `json:"refresh_token"`
	DownstreamToken    string   `json:"downstream_token"`
	TokenType          string   `json:"token_type"`
	SessionID          string   `json:"session_id"`
	TokenID            string   `json:"token_id"`
	PrincipalID        string   `json:"principal_id"`
	TokenFamilyID      string   `json:"token_family_id"`
	Scopes             []string `json:"scopes"`
	IssuedAtMs         int64    `json:"issued_at_ms"`
	AccessExpiresAtMs  int64    `json:"access_expires_at_ms"`
	RefreshExpiresAtMs int64    `json:"refresh_expires_at_ms"`
	Persisted          bool     `json:"persisted"`
}
