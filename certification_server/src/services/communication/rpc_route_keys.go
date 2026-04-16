package communication

const (
	bootstrapChallengeRouteKey            = "auth.bootstrap.challenge"
	bootstrapAuthenticateRouteKey         = "auth.bootstrap.authenticate"
	remoteAuthVerifyRouteKey              = "auth.remote.verify.token"
	remoteSessionValidateRouteKey         = "auth.remote.validate.session"
	externalAuthForwardRouteKey           = "auth.external.forward.user_password"
	externalRefreshTokenBundleRouteKey    = "auth.external.forward.token_refresh_bundle"
	externalBootstrapChallengeRouteKey    = "auth.external.forward.bootstrap.challenge"
	externalBootstrapAuthenticateRouteKey = "auth.external.forward.bootstrap.authenticate"
	moduleTokenRefreshRouteKey            = "auth.module.refresh.token_bundle"
)

const (
	BootstrapChallengeRouteKey            = bootstrapChallengeRouteKey
	BootstrapAuthenticateRouteKey         = bootstrapAuthenticateRouteKey
	RemoteAuthVerifyRouteKey              = remoteAuthVerifyRouteKey
	RemoteSessionValidateRouteKey         = remoteSessionValidateRouteKey
	ExternalAuthForwardRouteKey           = externalAuthForwardRouteKey
	ExternalRefreshTokenBundleRouteKey    = externalRefreshTokenBundleRouteKey
	ExternalBootstrapChallengeRouteKey    = externalBootstrapChallengeRouteKey
	ExternalBootstrapAuthenticateRouteKey = externalBootstrapAuthenticateRouteKey
	ModuleTokenRefreshRouteKey            = moduleTokenRefreshRouteKey
)
