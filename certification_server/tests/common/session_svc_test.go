package common_test

import (
	"context"
	"errors"
	"testing"
	"time"

	iface "certification_server/src/iface/common"
	authmodel "certification_server/src/models/auth"
	commonmodel "certification_server/src/models/common"
	modelsystem "certification_server/src/models/system"
	commonservice "certification_server/src/services/common"

	"github.com/google/uuid"
)

func assertSessionError(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error %q, got nil", want)
	}
	var sysErr *modelsystem.Error
	if !errors.As(err, &sysErr) {
		t.Fatalf("expected system error %q, got %T", want, err)
	}
	if sysErr.Error() != want {
		t.Fatalf("expected %q, got %q", want, sysErr.Error())
	}
}

func TestSessionServiceLifecycle(t *testing.T) {
	svc := commonservice.NewSessionService(nil)
	principal := authmodel.Principal{EntityType: commonmodel.EntityUser, EntityID: "alice"}

	session, err := svc.CreateSession(context.Background(), &iface.SessionIssueRequest{
		Principal:  principal,
		Role:       "admin",
		Scopes:     []string{"user:read"},
		AuthMethod: authmodel.AuthMethodPassword,
		ClientID:   "client-1",
		GatewayID:  "gateway-1",
		SourceIP:   "127.0.0.1",
		UserAgent:  "test-agent",
		ExpiresAt:  time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if session == nil {
		t.Fatalf("expected session")
	}
	if session.PrincipalID != "user:alice" {
		t.Fatalf("unexpected principal id: %s", session.PrincipalID)
	}
	if session.Status != authmodel.SessionActive {
		t.Fatalf("expected active session, got %s", session.Status)
	}
	if session.TokenFamilyID == uuid.Nil {
		t.Fatalf("expected token family id")
	}

	fetched, err := svc.GetSession(context.Background(), session.ID.String())
	if err != nil {
		t.Fatalf("unexpected get error: %v", err)
	}
	if fetched.ID != session.ID {
		t.Fatalf("expected fetched session id %s, got %s", session.ID, fetched.ID)
	}

	if err := svc.TouchSession(context.Background(), session.ID.String(), authmodel.SessionTouchMeta{
		SourceIP:  "10.0.0.1",
		UserAgent: "updated-agent",
		ClientID:  "client-2",
		GatewayID: "gateway-2",
	}); err != nil {
		t.Fatalf("unexpected touch error: %v", err)
	}

	updated, err := svc.GetSession(context.Background(), session.ID.String())
	if err != nil {
		t.Fatalf("unexpected get after touch error: %v", err)
	}
	if updated.LastSeenIP != "10.0.0.1" || updated.UserAgent != "updated-agent" || updated.ClientID != "client-2" || updated.GatewayID != "gateway-2" {
		t.Fatalf("touch did not update session metadata: %+v", updated)
	}
	if updated.Version != 2 {
		t.Fatalf("expected version increment, got %d", updated.Version)
	}

	validated, err := svc.ValidateSession(context.Background(), &iface.SessionValidateRequest{
		SessionID:     session.ID,
		PrincipalID:   session.PrincipalID,
		RequireActive: true,
		MinVersion:    2,
	})
	if err != nil {
		t.Fatalf("unexpected validate error: %v", err)
	}
	if validated.ID != session.ID {
		t.Fatalf("unexpected validated session id: %s", validated.ID)
	}

	if err := svc.RevokeSession(context.Background(), &iface.SessionRevokeRequest{SessionID: session.ID}); err != nil {
		t.Fatalf("unexpected revoke error: %v", err)
	}
	_, err = svc.ValidateSession(context.Background(), &iface.SessionValidateRequest{
		SessionID:     session.ID,
		PrincipalID:   session.PrincipalID,
		RequireActive: true,
	})
	assertSessionError(t, err, modelsystem.ErrSessionNotActive.Error())

	second, err := svc.CreateSession(context.Background(), &iface.SessionIssueRequest{
		Principal:  principal,
		Role:       "user",
		AuthMethod: authmodel.AuthMethodPassword,
		ExpiresAt:  time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("unexpected second session error: %v", err)
	}
	if err := svc.RevokePrincipalSessions(context.Background(), principal.PrincipalID(), "test", "tester"); err != nil {
		t.Fatalf("unexpected revoke principal error: %v", err)
	}
	_, err = svc.ValidateSession(context.Background(), &iface.SessionValidateRequest{
		SessionID:     second.ID,
		PrincipalID:   second.PrincipalID,
		RequireActive: true,
	})
	assertSessionError(t, err, modelsystem.ErrSessionNotActive.Error())

	third, err := svc.CreateSession(context.Background(), &iface.SessionIssueRequest{
		Principal:  principal,
		Role:       "user",
		AuthMethod: authmodel.AuthMethodPassword,
		ExpiresAt:  time.Now().Add(-time.Minute),
	})
	if err != nil {
		t.Fatalf("unexpected third session error: %v", err)
	}
	_, err = svc.ValidateSession(context.Background(), &iface.SessionValidateRequest{SessionID: third.ID})
	assertSessionError(t, err, modelsystem.ErrSessionExpired.Error())
}

func TestSessionServiceErrors(t *testing.T) {
	svc := commonservice.NewSessionService(nil)
	if _, err := svc.CreateSession(context.Background(), nil); err == nil {
		t.Fatalf("expected create session error")
	}
	if _, err := svc.GetSession(context.Background(), "bad-id"); err == nil {
		t.Fatalf("expected get session parse error")
	}
	if err := svc.TouchSession(context.Background(), "bad-id", authmodel.SessionTouchMeta{}); err == nil {
		t.Fatalf("expected touch parse error")
	}
	if _, err := svc.ValidateSession(context.Background(), nil); err == nil {
		t.Fatalf("expected validate nil error")
	}
	if err := svc.RevokeSession(context.Background(), nil); err == nil {
		t.Fatalf("expected revoke nil error")
	}
	if err := svc.RevokePrincipalSessions(context.Background(), "", "", ""); err == nil {
		t.Fatalf("expected revoke principal id error")
	}
}
