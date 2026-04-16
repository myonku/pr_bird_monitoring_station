package authcontrol_test

import (
	"errors"
	"testing"

	authcontrol "certification_server/src/iface/authcontrol"
	authmodel "certification_server/src/models/auth"
	commonmodel "certification_server/src/models/common"
	modelsystem "certification_server/src/models/system"

	"github.com/google/uuid"
)

func TestBuildInboundRateLimitDescriptor(t *testing.T) {
	descriptor, err := authcontrol.Build(nil)
	if err == nil {
		t.Fatalf("expected error for nil input")
	}
	var sysErr *modelsystem.Error
	if !errors.As(err, &sysErr) {
		t.Fatalf("expected system error, got %T", err)
	}
	if sysErr.ErrType != modelsystem.RateLimitErr {
		t.Fatalf("expected rate limit error, got %s", sysErr.ErrType)
	}
	if descriptor != nil {
		t.Fatalf("expected nil descriptor for nil input")
	}

	identity := &authmodel.IdentityContext{
		Principal: authmodel.Principal{
			EntityType: commonmodel.EntityUser,
			EntityID:   "user-1",
		},
		EntityType:  commonmodel.EntityUser,
		EntityID:    "user-1",
		SessionID:   uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		TokenID:     uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		TokenType:   authmodel.TokenAccess,
		PrincipalID: "user:user-1",
	}

	descriptor, err = authcontrol.Build(&authcontrol.InboundRateLimitInput{
		Scope:         authmodel.RateLimitScopeAuth,
		Transport:     "grpc",
		Module:        "auth",
		Action:        "verify",
		Route:         "auth.verify",
		Method:        "POST",
		SourceIP:      "127.0.0.1",
		GatewayID:     "gateway-1",
		ClientID:      "client-1",
		SourceService: "gateway",
		TargetService: "certification_server",
		Tags:          map[string]string{"env": "test"},
		Identity:      identity,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !descriptor.Authenticated {
		t.Fatalf("expected authenticated descriptor")
	}
	if descriptor.EntityID != "user-1" {
		t.Fatalf("expected entity id to be copied, got %q", descriptor.EntityID)
	}
	if descriptor.PrincipalID != "user:user-1" {
		t.Fatalf("expected principal id to be copied, got %q", descriptor.PrincipalID)
	}
	if descriptor.SessionID != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("expected session id to be copied, got %q", descriptor.SessionID)
	}
	if descriptor.TokenID != "22222222-2222-2222-2222-222222222222" {
		t.Fatalf("expected token id to be copied, got %q", descriptor.TokenID)
	}
	if descriptor.Tags["env"] != "test" {
		t.Fatalf("expected tags to be preserved")
	}
}
