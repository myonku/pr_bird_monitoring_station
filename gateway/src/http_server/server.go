package http_server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"gateway/src/app"
	authif "gateway/src/interfaces/auth"
	modelsystem "gateway/src/models/system"
)

var _ app.HTTPServerPort = (*Server)(nil)

// ServerOptions 定义网关 HTTP 服务参数。
type ServerOptions struct {
	Address      string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

// Server 封装网关 HTTP 服务启动与关闭。
type Server struct {
	httpServer *http.Server
}

// NewServer 创建网关 HTTP 服务。
func NewServer(opts ServerOptions, userAuthClient authif.IUserCredentialAuthClient) *Server {
	if opts.Address == "" {
		opts.Address = ":8080"
	}
	if opts.ReadTimeout <= 0 {
		opts.ReadTimeout = 10 * time.Second
	}
	if opts.WriteTimeout <= 0 {
		opts.WriteTimeout = 15 * time.Second
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = 60 * time.Second
	}

	return &Server{
		httpServer: &http.Server{
			Addr:         opts.Address,
			Handler:      NewRouter(userAuthClient),
			ReadTimeout:  opts.ReadTimeout,
			WriteTimeout: opts.WriteTimeout,
			IdleTimeout:  opts.IdleTimeout,
		},
	}
}

// Start 启动 HTTP 服务并响应上下文取消。
func (s *Server) Start(ctx context.Context) error {
	if s == nil || s.httpServer == nil {
		return &modelsystem.ErrHTTPServerNotConfigured
	}

	errCh := make(chan error, 1)
	go func() {
		err := s.httpServer.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Stop(shutdownCtx)
		return ctx.Err()
	case err := <-errCh:
		if err == nil {
			return nil
		}
		return err
	}
}

// Stop 停止 HTTP 服务。
func (s *Server) Stop(ctx context.Context) error {
	if s == nil || s.httpServer == nil {
		return &modelsystem.ErrHTTPServerNotConfigured
	}
	if ctx == nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.httpServer.Shutdown(shutdownCtx)
	}
	return s.httpServer.Shutdown(ctx)
}
