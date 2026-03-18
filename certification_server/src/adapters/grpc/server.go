package grpcadapter

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// RegisterServiceFunc 定义 gRPC 服务注册函数。
type RegisterServiceFunc func(registrar grpc.ServiceRegistrar)

// ServerOptions 定义 gRPC 服务端初始化参数。
type ServerOptions struct {
	Address string

	TLSConfig *tls.Config

	UnaryInterceptors  []grpc.UnaryServerInterceptor
	StreamInterceptors []grpc.StreamServerInterceptor

	RegisterServices []RegisterServiceFunc
}

// Server 是认证中心 gRPC 入站适配器。
type Server struct {
	opts ServerOptions

	mu     sync.Mutex
	lis    net.Listener
	server *grpc.Server
}

// NewServer 创建 gRPC 服务端适配器。
func NewServer(opts ServerOptions) (*Server, error) {
	if opts.Address == "" {
		opts.Address = ":50051"
	}
	return &Server{opts: opts}, nil
}

// Start 启动 gRPC server，直到 context 取消或 Serve 返回错误。
func (s *Server) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	if s.server != nil {
		s.mu.Unlock()
		return errors.New("grpc server already started")
	}

	lis, err := net.Listen("tcp", s.opts.Address)
	if err != nil {
		s.mu.Unlock()
		return err
	}

	serverOpts := make([]grpc.ServerOption, 0)
	if s.opts.TLSConfig != nil {
		serverOpts = append(serverOpts, grpc.Creds(credentials.NewTLS(s.opts.TLSConfig)))
	}
	if len(s.opts.UnaryInterceptors) > 0 {
		serverOpts = append(serverOpts, grpc.ChainUnaryInterceptor(s.opts.UnaryInterceptors...))
	}
	if len(s.opts.StreamInterceptors) > 0 {
		serverOpts = append(serverOpts, grpc.ChainStreamInterceptor(s.opts.StreamInterceptors...))
	}

	grpcServer := grpc.NewServer(serverOpts...)
	for _, register := range s.opts.RegisterServices {
		if register != nil {
			register(grpcServer)
		}
	}

	s.lis = lis
	s.server = grpcServer
	s.mu.Unlock()

	errCh := make(chan error, 1)
	go func() {
		errCh <- grpcServer.Serve(lis)
	}()

	select {
	case <-ctx.Done():
		_ = s.Stop(context.Background())
		return ctx.Err()
	case serveErr := <-errCh:
		_ = s.Stop(context.Background())
		if serveErr == nil {
			return nil
		}
		return serveErr
	}
}

// Stop 停止 gRPC server。
func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	grpcServer := s.server
	lis := s.lis
	s.server = nil
	s.lis = nil
	s.mu.Unlock()

	if grpcServer == nil {
		return nil
	}

	done := make(chan struct{}, 1)
	go func() {
		grpcServer.GracefulStop()
		done <- struct{}{}
	}()

	if ctx == nil {
		ctx = context.Background()
	}

	select {
	case <-done:
	case <-ctx.Done():
		grpcServer.Stop()
		if lis != nil {
			_ = lis.Close()
		}
		return ctx.Err()
	case <-time.After(5 * time.Second):
		grpcServer.Stop()
	}

	if lis != nil {
		_ = lis.Close()
	}
	return nil
}
