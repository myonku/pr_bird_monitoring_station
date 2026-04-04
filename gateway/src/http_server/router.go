package http_server

import (
	"net/http"
	"time"

	authif "gateway/src/interfaces/auth"
)

// NewRouter 构建网关 HTTP 路由。
func NewRouter(userAuthClient authif.IUserCredentialAuthClient) *http.ServeMux {
	mux := http.NewServeMux()

	authHandler := NewAuthHTTPHandler(userAuthClient)
	authHandler.RegisterRoutes(mux)

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"status":    "ok",
			"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		})
	})

	return mux
}
