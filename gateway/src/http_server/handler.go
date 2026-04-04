package http_server

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	authif "gateway/src/interfaces/auth"
	authmodel "gateway/src/models/auth"
	modelsystem "gateway/src/models/system"

	"github.com/google/uuid"
)

// AuthHTTPHandler 提供客户端认证相关 HTTP 入站处理。
type AuthHTTPHandler struct {
	UserAuthClient authif.IUserCredentialAuthClient
}

func NewAuthHTTPHandler(userAuthClient authif.IUserCredentialAuthClient) *AuthHTTPHandler {
	return &AuthHTTPHandler{UserAuthClient: userAuthClient}
}

// RegisterRoutes 注册客户端认证相关路由。
func (h *AuthHTTPHandler) RegisterRoutes(mux *http.ServeMux) {
	if mux == nil {
		return
	}
	mux.HandleFunc("/v1/client/auth/login", h.handleLogin)
	mux.HandleFunc("/v1/client/auth/token/refresh", h.handleRefresh)
	mux.HandleFunc("/v1/client/auth/token/verify", h.handleVerify)
	mux.HandleFunc("/v1/client/auth/token/revoke", h.handleRevoke)
	mux.HandleFunc("/v1/client/auth/logout", h.handleLogout)
}

type loginRequest struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	Audience string   `json:"audience"`
	Scopes   []string `json:"scopes"`

	ClientID  string `json:"client_id"`
	GatewayID string `json:"gateway_id"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
	ClientID     string `json:"client_id"`
	GatewayID    string `json:"gateway_id"`
}

type verifyRequest struct {
	AccessToken      string   `json:"access_token"`
	ExpectedTypes    []string `json:"expected_types"`
	ExpectedAudience string   `json:"expected_audience"`
	RequireScopes    []string `json:"require_scopes"`
}

type revokeRequest struct {
	TokenID   string `json:"token_id"`
	FamilyID  string `json:"family_id"`
	SessionID string `json:"session_id"`

	Reason    string `json:"reason"`
	RevokedBy string `json:"revoked_by"`
}

type logoutRequest struct {
	SessionID    string `json:"session_id"`
	RefreshToken string `json:"refresh_token"`

	Reason    string `json:"reason"`
	RevokedBy string `json:"revoked_by"`
}

func (h *AuthHTTPHandler) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "only POST is supported")
		return
	}
	if !h.ensureClient(w) {
		return
	}

	var body loginRequest
	if err := decodeJSONBody(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	req := &authmodel.UserPasswordAuthRequest{
		Username:  strings.TrimSpace(body.Username),
		Password:  body.Password,
		Audience:  strings.TrimSpace(body.Audience),
		Scopes:    append([]string(nil), body.Scopes...),
		ClientID:  firstNonEmpty(strings.TrimSpace(body.ClientID), r.Header.Get("X-Client-ID")),
		GatewayID: firstNonEmpty(strings.TrimSpace(body.GatewayID), r.Header.Get("X-Gateway-ID")),
		SourceIP:  remoteIP(r),
		UserAgent: r.UserAgent(),
		RequestID: firstNonEmpty(strings.TrimSpace(r.Header.Get("X-Request-ID")), uuid.NewString()),
		TraceID:   firstNonEmpty(strings.TrimSpace(r.Header.Get("X-Trace-ID")), uuid.NewString()),
	}

	result, err := h.UserAuthClient.AuthenticateByPassword(r.Context(), req)
	if err != nil {
		writeError(w, statusFromError(err), "auth_failed", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func (h *AuthHTTPHandler) handleRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "only POST is supported")
		return
	}
	if !h.ensureClient(w) {
		return
	}

	var body refreshRequest
	if err := decodeJSONBody(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	bundle, err := h.UserAuthClient.RefreshByUserSession(r.Context(), &authmodel.TokenRefreshRequest{
		RefreshToken: strings.TrimSpace(body.RefreshToken),
		ClientID:     firstNonEmpty(strings.TrimSpace(body.ClientID), r.Header.Get("X-Client-ID")),
		GatewayID:    firstNonEmpty(strings.TrimSpace(body.GatewayID), r.Header.Get("X-Gateway-ID")),
		SourceIP:     remoteIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    firstNonEmpty(strings.TrimSpace(r.Header.Get("X-Request-ID")), uuid.NewString()),
		TraceID:      firstNonEmpty(strings.TrimSpace(r.Header.Get("X-Trace-ID")), uuid.NewString()),
	})
	if err != nil {
		writeError(w, statusFromError(err), "refresh_failed", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, bundle)
}

func (h *AuthHTTPHandler) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "only POST is supported")
		return
	}
	if !h.ensureClient(w) {
		return
	}

	var body verifyRequest
	if err := decodeJSONBody(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	expectedTypes := parseTokenTypes(body.ExpectedTypes)
	if len(expectedTypes) == 0 {
		expectedTypes = []authmodel.TokenType{authmodel.TokenAccess}
	}

	result, err := h.UserAuthClient.VerifyUserToken(r.Context(), &authmodel.TokenVerifyRequest{
		RawToken:            strings.TrimSpace(body.AccessToken),
		ExpectedTypes:       expectedTypes,
		ExpectedAudience:    strings.TrimSpace(body.ExpectedAudience),
		RequireScopes:       append([]string(nil), body.RequireScopes...),
		AllowExpiredSkewSec: 0,
	})
	if err != nil {
		writeError(w, statusFromError(err), "verify_failed", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func (h *AuthHTTPHandler) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "only POST is supported")
		return
	}
	if !h.ensureClient(w) {
		return
	}

	var body revokeRequest
	if err := decodeJSONBody(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	tokenID, err := parseOptionalUUID(body.TokenID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_token_id", err.Error())
		return
	}
	familyID, err := parseOptionalUUID(body.FamilyID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_family_id", err.Error())
		return
	}
	sessionID, err := parseOptionalUUID(body.SessionID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_session_id", err.Error())
		return
	}

	if sessionID != uuid.Nil && tokenID == uuid.Nil && familyID == uuid.Nil {
		err = h.UserAuthClient.RevokeUserSession(r.Context(), &authmodel.SessionRevokeRequest{
			SessionID: sessionID,
			Reason:    strings.TrimSpace(body.Reason),
			RevokedBy: strings.TrimSpace(body.RevokedBy),
			RequestID: firstNonEmpty(strings.TrimSpace(r.Header.Get("X-Request-ID")), uuid.NewString()),
			TraceID:   firstNonEmpty(strings.TrimSpace(r.Header.Get("X-Trace-ID")), uuid.NewString()),
		})
	} else {
		err = h.UserAuthClient.RevokeUserToken(r.Context(), &authmodel.TokenRevokeRequest{
			TokenID:   tokenID,
			FamilyID:  familyID,
			SessionID: sessionID,
			Reason:    strings.TrimSpace(body.Reason),
			RevokedBy: strings.TrimSpace(body.RevokedBy),
			RequestID: firstNonEmpty(strings.TrimSpace(r.Header.Get("X-Request-ID")), uuid.NewString()),
			TraceID:   firstNonEmpty(strings.TrimSpace(r.Header.Get("X-Trace-ID")), uuid.NewString()),
		})
	}
	if err != nil {
		writeError(w, statusFromError(err), "revoke_failed", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *AuthHTTPHandler) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "only POST is supported")
		return
	}
	if !h.ensureClient(w) {
		return
	}

	var body logoutRequest
	if err := decodeJSONBody(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	requestID := firstNonEmpty(strings.TrimSpace(r.Header.Get("X-Request-ID")), uuid.NewString())
	traceID := firstNonEmpty(strings.TrimSpace(r.Header.Get("X-Trace-ID")), uuid.NewString())

	if strings.TrimSpace(body.SessionID) != "" {
		sessionID, err := uuid.Parse(strings.TrimSpace(body.SessionID))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_session_id", err.Error())
			return
		}
		err = h.UserAuthClient.RevokeUserSession(r.Context(), &authmodel.SessionRevokeRequest{
			SessionID: sessionID,
			Reason:    strings.TrimSpace(body.Reason),
			RevokedBy: strings.TrimSpace(body.RevokedBy),
			RequestID: requestID,
			TraceID:   traceID,
		})
		if err != nil {
			writeError(w, statusFromError(err), "logout_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}

	refreshToken := strings.TrimSpace(body.RefreshToken)
	if refreshToken == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", modelsystem.ErrSessionIDOrRefreshRequired.Error())
		return
	}

	verified, err := h.UserAuthClient.VerifyUserToken(r.Context(), &authmodel.TokenVerifyRequest{
		RawToken:      refreshToken,
		ExpectedTypes: []authmodel.TokenType{authmodel.TokenRefresh},
	})
	if err != nil {
		writeError(w, statusFromError(err), "logout_failed", err.Error())
		return
	}
	if verified == nil || !verified.Valid || verified.Identity == nil {
		writeError(w, http.StatusUnauthorized, "invalid_token", "refresh token is invalid")
		return
	}

	revokeReq := &authmodel.TokenRevokeRequest{
		FamilyID:  verified.Identity.TokenFamilyID,
		TokenID:   verified.Identity.TokenID,
		SessionID: verified.Identity.SessionID,
		Reason:    strings.TrimSpace(body.Reason),
		RevokedBy: strings.TrimSpace(body.RevokedBy),
		RequestID: requestID,
		TraceID:   traceID,
	}
	if err = h.UserAuthClient.RevokeUserToken(r.Context(), revokeReq); err != nil {
		writeError(w, statusFromError(err), "logout_failed", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *AuthHTTPHandler) ensureClient(w http.ResponseWriter) bool {
	if h == nil || h.UserAuthClient == nil {
		writeError(w, http.StatusInternalServerError, "dependency_error", modelsystem.ErrUserAuthClientNotConfigured.Error())
		return false
	}
	return true
}

func decodeJSONBody(r *http.Request, out interface{}) error {
	if r == nil || r.Body == nil {
		return errors.New("request body is empty")
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, statusCode int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, statusCode int, code string, message string) {
	if code == "" {
		code = "request_failed"
	}
	writeJSON(w, statusCode, map[string]string{
		"code":      code,
		"message":   message,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func statusFromError(err error) int {
	if err == nil {
		return http.StatusOK
	}
	var sysErr *modelsystem.Error
	if errors.As(err, &sysErr) {
		msg := strings.ToLower(sysErr.Info)
		switch {
		case strings.Contains(msg, "invalid user credentials"):
			return http.StatusUnauthorized
		case strings.Contains(msg, "required"), strings.Contains(msg, "request is nil"):
			return http.StatusBadRequest
		case strings.Contains(msg, "not found"):
			return http.StatusNotFound
		default:
			return http.StatusInternalServerError
		}
	}
	return http.StatusInternalServerError
}

func parseTokenTypes(values []string) []authmodel.TokenType {
	out := make([]authmodel.TokenType, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(strings.ToLower(value))
		if value == "" {
			continue
		}
		out = append(out, authmodel.TokenType(value))
	}
	return out
}

func parseOptionalUUID(raw string) (uuid.UUID, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return uuid.Nil, nil
	}
	return uuid.Parse(raw)
}

func remoteIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
