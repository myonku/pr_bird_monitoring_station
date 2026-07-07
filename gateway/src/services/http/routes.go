package gatewayhttp

import "strings"

type RouteKind string

const (
	RouteKindAuth     RouteKind = "auth"
	RouteKindBusiness RouteKind = "business"
	RouteKindHealth   RouteKind = "health"
)

type AuthRouteKind string

const (
	AuthRouteClientSignIn              AuthRouteKind = "client_sign_in"
	AuthRouteClientRefreshSession      AuthRouteKind = "client_refresh_session"
	AuthRouteEdgeBootstrapChallenge    AuthRouteKind = "edge_bootstrap_challenge"
	AuthRouteEdgeBootstrapAuthenticate AuthRouteKind = "edge_bootstrap_authenticate"
	AuthRouteEdgeTokenRefresh          AuthRouteKind = "edge_token_refresh"
)

type RouteSpec struct {
	Kind RouteKind

	Method string
	path   string

	routeKey  string
	operation string

	ExpectedTargetService string
	authRequired          bool
	AuthRoute             AuthRouteKind
}

const businessForwardRouteKey = "business.forward.generic"

func LookupRouteSpec(method string, path string) (RouteSpec, bool) {
	method = strings.ToUpper(strings.TrimSpace(method))
	path = strings.TrimSpace(path)

	switch path {
	case "/health", "/healthz":
		if method == "GET" {
			return RouteSpec{
				Kind:      RouteKindHealth,
				Method:    method,
				path:      path,
				routeKey:  "system.health",
				operation: "system.health",
			}, true
		}
	case "/v1/client/auth/sign-in":
		if method == "POST" {
			return RouteSpec{
				Kind:                  RouteKindAuth,
				Method:                method,
				path:                  path,
				routeKey:              "auth.external.forward.user_password",
				operation:             "client.auth.sign_in",
				ExpectedTargetService: "certification_server",
				AuthRoute:             AuthRouteClientSignIn,
			}, true
		}
	case "/v1/client/auth/refresh-session":
		if method == "POST" {
			return RouteSpec{
				Kind:                  RouteKindAuth,
				Method:                method,
				path:                  path,
				routeKey:              "auth.external.forward.token_refresh_bundle",
				operation:             "client.auth.refresh_session",
				ExpectedTargetService: "certification_server",
				AuthRoute:             AuthRouteClientRefreshSession,
			}, true
		}
	case "/v1/edge/auth/bootstrap/challenge":
		if method == "POST" {
			return RouteSpec{
				Kind:                  RouteKindAuth,
				Method:                method,
				path:                  path,
				routeKey:              "auth.external.forward.bootstrap.challenge",
				operation:             "edge.auth.bootstrap_challenge",
				ExpectedTargetService: "certification_server",
				AuthRoute:             AuthRouteEdgeBootstrapChallenge,
			}, true
		}
	case "/v1/edge/auth/bootstrap/authenticate":
		if method == "POST" {
			return RouteSpec{
				Kind:                  RouteKindAuth,
				Method:                method,
				path:                  path,
				routeKey:              "auth.external.forward.bootstrap.authenticate",
				operation:             "edge.auth.bootstrap_authenticate",
				ExpectedTargetService: "certification_server",
				AuthRoute:             AuthRouteEdgeBootstrapAuthenticate,
			}, true
		}
	case "/v1/edge/auth/token/refresh":
		if method == "POST" {
			return RouteSpec{
				Kind:                  RouteKindAuth,
				Method:                method,
				path:                  path,
				routeKey:              "auth.external.forward.token_refresh_bundle",
				operation:             "edge.auth.token_refresh",
				ExpectedTargetService: "certification_server",
				AuthRoute:             AuthRouteEdgeTokenRefresh,
			}, true
		}
	case "/v1/client/users/register":
		if method == "POST" {
			return RouteSpec{
				Kind:                  RouteKindBusiness,
				Method:                method,
				path:                  path,
				routeKey:              businessForwardRouteKey,
				operation:             "client.users.register",
				ExpectedTargetService: "data_server",
				authRequired:          false,
			}, true
		}
	case "/v1/client/users/profile":
		if method == "GET" {
			return RouteSpec{
				Kind:                  RouteKindBusiness,
				Method:                method,
				path:                  path,
				routeKey:              businessForwardRouteKey,
				operation:             "client.users.profile",
				ExpectedTargetService: "data_server",
				authRequired:          true,
			}, true
		}
	case "/v1/client/home/summary":
		if method == "GET" {
			return RouteSpec{
				Kind:                  RouteKindBusiness,
				Method:                method,
				path:                  path,
				routeKey:              businessForwardRouteKey,
				operation:             "client.home.summary",
				ExpectedTargetService: "data_server",
				authRequired:          true,
			}, true
		}
	case "/v1/client/records/stations":
		if method == "GET" {
			return RouteSpec{
				Kind:                  RouteKindBusiness,
				Method:                method,
				path:                  path,
				routeKey:              businessForwardRouteKey,
				operation:             "client.records.station_options",
				ExpectedTargetService: "data_server",
				authRequired:          true,
			}, true
		}
	case "/v1/client/records":
		if method == "GET" {
			return RouteSpec{
				Kind:                  RouteKindBusiness,
				Method:                method,
				path:                  path,
				routeKey:              businessForwardRouteKey,
				operation:             "client.records.cursor",
				ExpectedTargetService: "data_server",
				authRequired:          true,
			}, true
		}
	case "/v1/client/stats/weekly-trend":
		if method == "GET" {
			return RouteSpec{
				Kind:                  RouteKindBusiness,
				Method:                method,
				path:                  path,
				routeKey:              businessForwardRouteKey,
				operation:             "client.stats.weekly_trend",
				ExpectedTargetService: "data_server",
				authRequired:          true,
			}, true
		}
	case "/v1/client/stats/range-summary":
		if method == "GET" {
			return RouteSpec{
				Kind:                  RouteKindBusiness,
				Method:                method,
				path:                  path,
				routeKey:              businessForwardRouteKey,
				operation:             "client.stats.range_summary",
				ExpectedTargetService: "data_server",
				authRequired:          true,
			}, true
		}
	case "/v1/client/chat/send":
		if method == "POST" {
			return RouteSpec{
				Kind:                  RouteKindBusiness,
				Method:                method,
				path:                  path,
				routeKey:              businessForwardRouteKey,
				operation:             "client.chat.send",
				ExpectedTargetService: "bms_copilot",
				authRequired:          true,
			}, true
		}
	case "/v1/client/chat/sessions":
		if method == "GET" {
			return RouteSpec{
				Kind:                  RouteKindBusiness,
				Method:                method,
				path:                  path,
				routeKey:              businessForwardRouteKey,
				operation:             "client.chat.sessions.list",
				ExpectedTargetService: "bms_copilot",
				authRequired:          true,
			}, true
		}
		if method == "POST" {
			return RouteSpec{
				Kind:                  RouteKindBusiness,
				Method:                method,
				path:                  path,
				routeKey:              businessForwardRouteKey,
				operation:             "client.chat.sessions.create",
				ExpectedTargetService: "bms_copilot",
				authRequired:          true,
			}, true
		}
	case "/v1/client/chat/sessions/detail":
		if method == "POST" {
			return RouteSpec{
				Kind:                  RouteKindBusiness,
				Method:                method,
				path:                  path,
				routeKey:              businessForwardRouteKey,
				operation:             "client.chat.sessions.detail",
				ExpectedTargetService: "bms_copilot",
				authRequired:          true,
			}, true
		}
	case "/v1/client/chat/sessions/delete":
		if method == "POST" {
			return RouteSpec{
				Kind:                  RouteKindBusiness,
				Method:                method,
				path:                  path,
				routeKey:              businessForwardRouteKey,
				operation:             "client.chat.sessions.delete",
				ExpectedTargetService: "bms_copilot",
				authRequired:          true,
			}, true
		}
	case "/v1/edge/events":
		if method == "POST" {
			return RouteSpec{
				Kind:                  RouteKindBusiness,
				Method:                method,
				path:                  path,
				routeKey:              businessForwardRouteKey,
				operation:             "edge.events.upload",
				ExpectedTargetService: "data_worker",
				authRequired:          true,
			}, true
		}
	}

	return RouteSpec{}, false
}
