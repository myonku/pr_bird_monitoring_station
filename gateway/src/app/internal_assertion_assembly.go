package app

import (
	"strings"

	outbound "gateway/src/adapters/outbound"
	commsecif "gateway/src/interfaces/commsec"
	commsecmodel "gateway/src/models/commsec"
	modelsystem "gateway/src/models/system"
	authsvc "gateway/src/services/auth"
)

// WireInternalAssertion 为 gRPC forwarder 注入内部断言签发能力。
// 该函数只负责装配，不改变其他转发行为。
func WireInternalAssertion(
	forwarder *outbound.GRPCOutboundForwarder,
	secretKeySvc commsecif.ISecretKeyService,
	cfg *modelsystem.ProjectConfig,
) error {
	if forwarder == nil {
		return &modelsystem.ErrGRPCOutboundDependenciesRequired
	}

	internalCfg := modelsystem.InternalAssertionConfig{}
	if cfg != nil {
		internalCfg = cfg.InternalAssertion.Normalized()
	} else {
		internalCfg = (&modelsystem.InternalAssertionConfig{}).Normalized()
	}

	if !internalCfg.Enabled {
		forwarder.EnableInternalAssertion = false
		forwarder.InternalAssertionSigner = nil
		forwarder.InternalAssertionHeader = internalCfg.HeaderName
		return nil
	}

	if secretKeySvc == nil {
		return &modelsystem.ErrInternalAssertionSignerRequired
	}

	signer := authsvc.NewDefaultInternalAssertionSigner(secretKeySvc)
	signer.DefaultTTLSeconds = internalCfg.TTLSeconds
	if internalCfg.Issuer != "" {
		signer.Issuer = internalCfg.Issuer
	}
	if alg := strings.ToLower(strings.TrimSpace(internalCfg.SignatureAlgorithm)); alg != "" {
		signer.DefaultSignatureAlgorithm = commsecmodel.SignatureAlgorithm(alg)
	}

	forwarder.EnableInternalAssertion = true
	forwarder.InternalAssertionSigner = signer
	forwarder.InternalAssertionHeader = internalCfg.HeaderName

	return nil
}
