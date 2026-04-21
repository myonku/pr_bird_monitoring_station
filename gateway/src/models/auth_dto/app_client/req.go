package appclient_auth_dto

// ClientSignInRequest 是客户端登录的请求载荷。
type ClientSignInRequest struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
}

// ClientRefreshSessionRequest 是客户端会话续期的请求载荷。
type ClientRefreshSessionRequest struct {
	SessionID     string   `json:"session_id"`
	RefreshToken  string   `json:"refresh_token"`
	TokenID       string   `json:"token_id"`
	TokenFamilyID string   `json:"token_family_id"`
	PrincipalID   string   `json:"principal_id"`
	Scopes        []string `json:"scopes"`
}
