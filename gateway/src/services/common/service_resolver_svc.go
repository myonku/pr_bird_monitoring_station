package common

import (
	"context"
	"strings"

	commonif "gateway/src/iface/common"
	commonmodel "gateway/src/models/common"
	modelsystem "gateway/src/models/system"
)

const defaultGatewayAuthAuthorityService = "certification_server"

const (
	bootstrapChallengeRouteKey            = "auth.bootstrap.challenge"
	bootstrapAuthenticateRouteKey         = "auth.bootstrap.authenticate"
	remoteAuthVerifyRouteKey              = "auth.remote.verify.token"
	remoteSessionValidateRouteKey         = "auth.remote.validate.session"
	externalAuthForwardRouteKey           = "auth.external.forward.user_password"
	externalBootstrapChallengeRouteKey    = "auth.external.forward.bootstrap.challenge"
	externalBootstrapAuthenticateRouteKey = "auth.external.forward.bootstrap.authenticate"
	businessForwardRouteKey               = "business.forward.generic"
	trustedInternalCallMetadataKey        = "trusted_internal_call"
)

const (
	bootstrapInitMethodPath                 = "/bms.auth.v1.AuthAuthorityBootstrapService/InitBootstrapChallenge"
	bootstrapAuthMethodPath                 = "/bms.auth.v1.AuthAuthorityBootstrapService/AuthenticateBootstrap"
	remoteVerifyMethodPath                  = "/bms.auth.v1.AuthAuthorityRemoteAuthService/VerifyToken"
	remoteSessionMethodPath                 = "/bms.auth.v1.AuthAuthorityRemoteAuthService/ValidateSession"
	externalAuthMethodPath                  = "/bms.auth.v1.AuthAuthorityExternalAuthService/ForwardUserPassword"
	externalBootstrapChallengeMethodPath    = "/bms.auth.v1.AuthAuthorityExternalAuthService/ForwardBootstrapChallenge"
	externalBootstrapAuthenticateMethodPath = "/bms.auth.v1.AuthAuthorityExternalAuthService/ForwardBootstrapAuthenticate"
)

var _ commonif.IServiceResolver = (*ServiceResolverService)(nil)

// ServiceResolverService 提供网关目标服务解析与路由画像最小实现。
type ServiceResolverService struct {
	registrySvc          commonif.IRegistryManager
	policySnapshotMgr    commonif.IPolicySnapshotManager
	authAuthorityService string
}

func NewServiceResolverService(
	registrySvc commonif.IRegistryManager,
	policySnapshotMgr commonif.IPolicySnapshotManager,
	authAuthorityService string,
) commonif.IServiceResolver {
	resolvedAuthority := strings.TrimSpace(authAuthorityService)
	if resolvedAuthority == "" {
		resolvedAuthority = defaultGatewayAuthAuthorityService
	}

	return &ServiceResolverService{
		registrySvc:          registrySvc,
		policySnapshotMgr:    policySnapshotMgr,
		authAuthorityService: resolvedAuthority,
	}
}

func (s *ServiceResolverService) ResolveServiceType(
	ctx context.Context,
	flow *commonif.FlowRouteInput,
) (commonif.TargetServiceType, error) {
	profile, err := s.ResolveRouteProfile(ctx, flow)
	if err != nil {
		return commonif.TargetServiceTypeUnknown, err
	}
	if profile == nil || profile.TargetServiceType == "" {
		return commonif.TargetServiceTypeUnknown, &modelsystem.ErrRouteRuleNotFound
	}
	return profile.TargetServiceType, nil
}

func (s *ServiceResolverService) ResolveTargetInstance(
	ctx context.Context,
	flow *commonif.FlowRouteInput,
) (*commonmodel.ServiceInstance, error) {
	_ = ctx

	if flow == nil {
		return nil, &modelsystem.ErrResolveTargetRequestNil
	}
	if s.registrySvc == nil {
		return nil, &modelsystem.ErrResolverDependenciesRequired
	}

	targetService := s.resolveTargetServiceName(flow, "")
	if targetService == "" {
		return nil, &modelsystem.ErrRouteRuleNotFound
	}

	affinity := strings.TrimSpace(flow.Metadata["affinity_key"])
	if affinity == "" {
		affinity = strings.TrimSpace(flow.SourceService)
	}

	return s.registrySvc.ChooseEndpoint(targetService, affinity, nil)
}

func (s *ServiceResolverService) ResolveRouteProfile(
	ctx context.Context,
	flow *commonif.FlowRouteInput,
) (*commonif.RouteProfile, error) {
	if flow == nil {
		return nil, &modelsystem.ErrResolveTargetRequestNil
	}

	category := resolveFlowCategory(flow)
	profile := &commonif.RouteProfile{
		FlowCategory: category,
	}

	if s.policySnapshotMgr != nil {
		snapshot, err := s.policySnapshotMgr.LoadPolicySnapshot(ctx, "")
		if err == nil && snapshot != nil {
			if mapped, ok := snapshot.RouteMappings[strings.TrimSpace(flow.RouteKey)]; ok {
				profile.TargetServiceType = mapped.TargetServiceType
				profile.TargetServiceName = mapped.TargetServiceName
				profile.FlowCategory = mapped.FlowCategory
				profile.SecurityPolicy = mapped.SecurityPolicy
			}
			if profile.TargetServiceName == "" {
				if mapped, ok := snapshot.RouteMappings[string(category)]; ok {
					profile.TargetServiceType = mapped.TargetServiceType
					profile.TargetServiceName = mapped.TargetServiceName
					if profile.FlowCategory == "" {
						profile.FlowCategory = mapped.FlowCategory
					}
					if profile.SecurityPolicy == "" {
						profile.SecurityPolicy = mapped.SecurityPolicy
					}
				}
			}
		}
	}

	targetName := s.resolveTargetServiceName(flow, category)
	if targetName != "" {
		profile.TargetServiceName = targetName
	}
	if profile.TargetServiceType == "" {
		if strings.EqualFold(profile.TargetServiceName, s.authAuthorityService) {
			profile.TargetServiceType = commonif.TargetServiceTypeAuthAuthority
		} else if strings.TrimSpace(profile.TargetServiceName) != "" {
			profile.TargetServiceType = commonif.TargetServiceTypeInternal
		}
	}
	if profile.FlowCategory == "" {
		profile.FlowCategory = category
	}
	if profile.SecurityPolicy == "" {
		profile.SecurityPolicy = resolveDefaultSecurityPolicy(profile.FlowCategory)
	}

	if strings.TrimSpace(profile.TargetServiceName) == "" {
		return nil, &modelsystem.ErrRouteRuleNotFound
	}
	if s.registrySvc != nil {
		affinity := strings.TrimSpace(flow.Metadata["affinity_key"])
		if affinity == "" {
			affinity = strings.TrimSpace(flow.SourceService)
		}
		target, err := s.registrySvc.ChooseEndpoint(profile.TargetServiceName, affinity, nil)
		if err == nil && target != nil {
			profile.TargetEndpoint = strings.TrimSpace(target.Endpoint)
		}
	}

	return profile, nil
}

func (s *ServiceResolverService) resolveTargetServiceName(
	flow *commonif.FlowRouteInput,
	category commonif.FlowCategory,
) string {
	if flow == nil {
		return ""
	}

	if isTrustedInternalCall(flow) {
		if hint := strings.TrimSpace(flow.TargetServiceHint); hint != "" {
			return hint
		}
	}
	if flow.Metadata != nil {
		if target := strings.TrimSpace(flow.Metadata["target_service"]); target != "" {
			return target
		}
	}

	if category == "" {
		category = resolveFlowCategory(flow)
	}
	switch category {
	case commonif.FlowCategoryBootstrapCall,
		commonif.FlowCategoryExternalAuthRelay,
		commonif.FlowCategoryRemoteAuthVerify:
		return s.authAuthorityService
	default:
		return ""
	}
}

func resolveFlowCategory(flow *commonif.FlowRouteInput) commonif.FlowCategory {
	if flow == nil {
		return ""
	}

	if category, ok := resolveRouteKeyCategory(flow.RouteKey); ok {
		return category
	}

	if category, ok := resolveStaticFlowCategory(flow); ok {
		return category
	}

	return ""
}

func resolveRouteKeyCategory(routeKey string) (commonif.FlowCategory, bool) {
	switch strings.TrimSpace(strings.ToLower(routeKey)) {
	case bootstrapChallengeRouteKey, bootstrapAuthenticateRouteKey:
		return commonif.FlowCategoryBootstrapCall, true
	case remoteAuthVerifyRouteKey, remoteSessionValidateRouteKey:
		return commonif.FlowCategoryRemoteAuthVerify, true
	case externalAuthForwardRouteKey,
		externalBootstrapChallengeRouteKey,
		externalBootstrapAuthenticateRouteKey:
		return commonif.FlowCategoryExternalAuthRelay, true
	case businessForwardRouteKey:
		return commonif.FlowCategoryBusinessForward, true
	}
	return "", false
}

func resolveStaticFlowCategory(flow *commonif.FlowRouteInput) (commonif.FlowCategory, bool) {
	if flow == nil {
		return "", false
	}
	if !strings.EqualFold(strings.TrimSpace(flow.Transport), "grpc") {
		return "", false
	}
	if !strings.EqualFold(strings.TrimSpace(flow.Method), "POST") {
		return "", false
	}
	switch strings.TrimSpace(strings.ToLower(flow.Path)) {
	case strings.ToLower(bootstrapInitMethodPath), strings.ToLower(bootstrapAuthMethodPath):
		return commonif.FlowCategoryBootstrapCall, true
	case strings.ToLower(remoteVerifyMethodPath), strings.ToLower(remoteSessionMethodPath):
		return commonif.FlowCategoryRemoteAuthVerify, true
	case strings.ToLower(externalAuthMethodPath),
		strings.ToLower(externalBootstrapChallengeMethodPath),
		strings.ToLower(externalBootstrapAuthenticateMethodPath):
		return commonif.FlowCategoryExternalAuthRelay, true
	default:
		return "", false
	}
}

func isTrustedInternalCall(flow *commonif.FlowRouteInput) bool {
	if flow == nil || flow.Metadata == nil {
		return false
	}
	value := strings.TrimSpace(strings.ToLower(flow.Metadata[trustedInternalCallMetadataKey]))
	return value == "true" || value == "1" || value == "yes" || value == "internal"
}

func resolveDefaultSecurityPolicy(category commonif.FlowCategory) commonif.SecurityPolicy {
	switch category {
	case commonif.FlowCategoryBootstrapCall:
		return commonif.SecurityPolicyOptional
	case commonif.FlowCategoryBusinessForward,
		commonif.FlowCategoryExternalAuthRelay,
		commonif.FlowCategoryRemoteAuthVerify:
		return commonif.SecurityPolicyRequired
	default:
		return commonif.SecurityPolicyOptional
	}
}
