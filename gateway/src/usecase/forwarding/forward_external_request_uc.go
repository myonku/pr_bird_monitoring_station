package forwarding

import (
	"context"
	"errors"

	commif "gateway/src/interfaces/communication"
)

// ForwardExternalRequest 定义 HTTP 入站请求经过标准化后的转发输入。
type ForwardExternalRequest struct {
	RouteKey string
	Method   string
	Path     string
	Headers  map[string]string
	Query    map[string]string
	Body     []byte

	AffinityKey  string
	RequiredTags []string

	SecurityRequest *commif.OutboundInvocationRequest
}

// IForwardExternalRequestUsecase 定义外部请求转发用例接口。
type IForwardExternalRequestUsecase interface {
	Execute(ctx context.Context, req *ForwardExternalRequest) (*commif.OutboundForwardResponse, error)
}

// ForwardExternalRequestUsecase 负责解析目标、准备安全上下文并执行转发。
type ForwardExternalRequestUsecase struct {
	Resolver          commif.IOutboundTargetResolver
	SecurityPreparer  commif.IOutboundInvocationSecurity
	OutboundForwarder commif.IOutboundForwarder
}

// Execute 按固定链路执行转发编排。
func (u *ForwardExternalRequestUsecase) Execute(
	ctx context.Context,
	req *ForwardExternalRequest,
) (*commif.OutboundForwardResponse, error) {
	if u == nil || u.Resolver == nil || u.SecurityPreparer == nil || u.OutboundForwarder == nil {
		return nil, errors.New("forwarding dependencies are required")
	}
	if req == nil || req.SecurityRequest == nil {
		return nil, errors.New("forwarding request is invalid")
	}

	resolved, err := u.Resolver.Resolve(ctx, &commif.ResolveTargetRequest{
		RouteKey:     req.RouteKey,
		Method:       req.Method,
		Path:         req.Path,
		Headers:      req.Headers,
		AffinityKey:  req.AffinityKey,
		RequiredTags: req.RequiredTags,
	})
	if err != nil {
		return nil, err
	}

	securityContext, err := u.SecurityPreparer.Prepare(ctx, req.SecurityRequest)
	if err != nil {
		return nil, err
	}

	forwardReq := &commif.OutboundForwardRequest{
		TargetService: resolved.ServiceName,
		Endpoint:      resolved.Endpoint,
		Method:        req.Method,
		TimeoutMS:     resolved.TimeoutMS,
		Path:          req.Path,
		Headers:       req.Headers,
		Body:          req.Body,
		Query:         req.Query,
	}

	outboundSecurity := &commif.OutboundSecurityContext{
		Grant:   securityContext.Grant,
		Channel: securityContext.Channel,
	}
	if securityContext.CipherText != "" {
		outboundSecurity.EncryptedPayload = []byte(securityContext.CipherText)
		outboundSecurity.EncryptedMeta = securityContext.Meta
	}

	return u.OutboundForwarder.Forward(ctx, forwardReq, outboundSecurity)
}
