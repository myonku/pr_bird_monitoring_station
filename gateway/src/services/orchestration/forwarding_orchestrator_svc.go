package orchestration

import (
	"context"
	"errors"

	iface "gateway/src/iface/orchestration"
	modelsystem "gateway/src/models/system"
)

var _ iface.IForwardingOrchestrator = (*ForwardingOrchestratorService)(nil)

var errForwardingOrchestratorNotImplemented = errors.New("forwarding orchestrator skeleton not implemented")

// ForwardingOrchestratorService 是网关转发编排的最小实现骨架。
type ForwardingOrchestratorService struct{}

// NewForwardingOrchestratorService 创建最小可编译编排服务骨架。
func NewForwardingOrchestratorService() *ForwardingOrchestratorService {
	return &ForwardingOrchestratorService{}
}

// HandleBusinessForward 处理业务转发骨架逻辑。
func (s *ForwardingOrchestratorService) HandleBusinessForward(
	ctx context.Context, req *iface.ForwardingRequest,
) (*iface.ForwardingResult, error) {
	if req == nil {
		return nil, &modelsystem.ErrForwardingRequestInvalid
	}
	return nil, errForwardingOrchestratorNotImplemented
}

// HandleExternalAuthForward 处理外部认证转发骨架逻辑。
func (s *ForwardingOrchestratorService) HandleExternalAuthForward(
	ctx context.Context, req *iface.ForwardingRequest,
) (*iface.ForwardingResult, error) {
	if req == nil {
		return nil, &modelsystem.ErrForwardingRequestInvalid
	}
	return nil, errForwardingOrchestratorNotImplemented
}
