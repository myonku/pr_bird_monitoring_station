package common_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
	"unsafe"

	iface "certification_server/src/iface/common"
	authmodel "certification_server/src/models/auth"
	commonmodel "certification_server/src/models/common"
	modelsystem "certification_server/src/models/system"
	commonservice "certification_server/src/services/common"
)

func assertTokenError(t *testing.T, err error, want string) {
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

func getTokenRecordByRaw(t *testing.T, svc *commonservice.TokenService, raw string) *authmodel.TokenRecord {
	t.Helper()
	field := reflect.ValueOf(svc).Elem().FieldByName("byRaw")
	if !field.IsValid() {
		t.Fatalf("byRaw field not found")
	}
	readable := reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
	value := readable.MapIndex(reflect.ValueOf(raw))
	if !value.IsValid() || value.IsNil() {
		t.Fatalf("token %q not found", raw)
	}
	return value.Interface().(*authmodel.TokenRecord)
}

func expireTokenByRaw(t *testing.T, svc *commonservice.TokenService, raw string) {
	t.Helper()
	record := getTokenRecordByRaw(t, svc, raw)
	record.ExpiresAt = time.Now().Add(-time.Minute)
}

func TestTokenServiceLifecycle(t *testing.T) {
	sessionSvc := commonservice.NewSessionService(nil)
	tokenSvc := commonservice.NewTokenService(nil, nil)
	principal := authmodel.Principal{EntityType: commonmodel.EntityUser, EntityID: "alice"}
	session, err := sessionSvc.CreateSession(context.Background(), &iface.SessionIssueRequest{
		Principal:  principal,
		Role:       "admin",
		Scopes:     []string{"user:read"},
		AuthMethod: authmodel.AuthMethodPassword,
		ExpiresAt:  time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("unexpected session creation error: %v", err)
	}

	issueReq := &iface.TokenIssueRequest{
		Principal:     principal,
		Audience:      "client",
		Role:          "admin",
		Scopes:        []string{"user:read"},
		AuthMethod:    authmodel.AuthMethodPassword,
		ClientID:      "client-1",
		GatewayID:     "gateway-1",
		SourceService: "gateway",
		TargetService: "certification_server",
	}
	bundle, err := tokenSvc.IssueTokenBundle(context.Background(), session, issueReq)
	if err != nil {
		t.Fatalf("unexpected issue bundle error: %v", err)
	}
	if bundle == nil || bundle.AccessToken == nil || bundle.RefreshToken == nil {
		t.Fatalf("expected access and refresh tokens")
	}
	if bundle.AccessToken.TTLSec != 6*60*60 {
		t.Fatalf("unexpected access token ttl: %d", bundle.AccessToken.TTLSec)
	}
	if bundle.RefreshToken.TTLSec != 7*24*60*60 {
		t.Fatalf("unexpected refresh token ttl: %d", bundle.RefreshToken.TTLSec)
	}

	verified, err := tokenSvc.VerifyToken(context.Background(), &iface.TokenVerifyRequest{RawToken: bundle.AccessToken.Raw})
	if err != nil {
		t.Fatalf("unexpected verify error: %v", err)
	}
	if !verified.Valid || verified.Identity == nil || verified.Identity.PrincipalID != principal.PrincipalID() {
		t.Fatalf("expected valid verification result, got %+v", verified)
	}

	expireTokenByRaw(t, tokenSvc, bundle.AccessToken.Raw)
	expired, err := tokenSvc.VerifyToken(context.Background(), &iface.TokenVerifyRequest{RawToken: bundle.AccessToken.Raw})
	if err != nil {
		t.Fatalf("unexpected expired verify error: %v", err)
	}
	if expired.Valid || expired.Status != authmodel.TokenStatusExpired {
		t.Fatalf("expected expired token result, got %+v", expired)
	}

	refreshBundle, err := tokenSvc.RefreshTokenBundle(context.Background(), &iface.TokenRefreshRequest{RefreshToken: bundle.RefreshToken.Raw})
	if err != nil {
		t.Fatalf("unexpected refresh error: %v", err)
	}
	if refreshBundle == nil || refreshBundle.AccessToken == nil || refreshBundle.RefreshToken == nil {
		t.Fatalf("expected refreshed tokens")
	}
	if refreshBundle.AccessToken.TTLSec != 6*60*60 {
		t.Fatalf("unexpected refreshed access token ttl: %d", refreshBundle.AccessToken.TTLSec)
	}
	if refreshBundle.RefreshToken.TTLSec != 7*24*60*60 {
		t.Fatalf("unexpected refreshed refresh token ttl: %d", refreshBundle.RefreshToken.TTLSec)
	}

	refreshVerified, err := tokenSvc.VerifyToken(context.Background(), &iface.TokenVerifyRequest{RawToken: bundle.RefreshToken.Raw})
	if err != nil {
		t.Fatalf("unexpected refresh verify error: %v", err)
	}
	if refreshVerified.Valid || refreshVerified.Status != authmodel.TokenStatusRotated {
		t.Fatalf("expected old refresh token to be rotated, got %+v", refreshVerified)
	}

	secondBundle, err := tokenSvc.IssueTokenBundle(context.Background(), session, issueReq)
	if err != nil {
		t.Fatalf("unexpected second issue error: %v", err)
	}
	if err := tokenSvc.RevokeToken(context.Background(), &iface.TokenRevokeRequest{TokenID: secondBundle.AccessToken.Claims.TokenID}); err != nil {
		t.Fatalf("unexpected revoke token error: %v", err)
	}
	revokedAccess, err := tokenSvc.VerifyToken(context.Background(), &iface.TokenVerifyRequest{RawToken: secondBundle.AccessToken.Raw})
	if err != nil {
		t.Fatalf("unexpected revoked access verify error: %v", err)
	}
	if revokedAccess.Valid || revokedAccess.Status != authmodel.TokenStatusRevoked {
		t.Fatalf("expected access token to be revoked, got %+v", revokedAccess)
	}

	if err := tokenSvc.RevokeTokenFamily(context.Background(), secondBundle.RefreshToken.Claims.FamilyID.String(), "tester"); err != nil {
		t.Fatalf("unexpected revoke family error: %v", err)
	}
	revokedRefresh, err := tokenSvc.VerifyToken(context.Background(), &iface.TokenVerifyRequest{RawToken: secondBundle.RefreshToken.Raw})
	if err != nil {
		t.Fatalf("unexpected revoked refresh verify error: %v", err)
	}
	if revokedRefresh.Valid || revokedRefresh.Status != authmodel.TokenStatusRevoked {
		t.Fatalf("expected refresh token to be revoked, got %+v", revokedRefresh)
	}
}

func TestTokenServiceErrors(t *testing.T) {
	tokenSvc := commonservice.NewTokenService(nil, nil)
	if _, err := tokenSvc.IssueToken(context.Background(), nil); err == nil {
		t.Fatalf("expected issue token error")
	}
	if _, err := tokenSvc.IssueTokenBundle(context.Background(), nil, nil); err == nil {
		t.Fatalf("expected issue bundle error")
	}
	assertTokenError(t, func() error {
		_, err := tokenSvc.RefreshTokenBundle(context.Background(), nil)
		return err
	}(), modelsystem.ErrRefreshTokenRequired.Error())
	if _, err := tokenSvc.VerifyToken(context.Background(), nil); err == nil {
		t.Fatalf("expected verify token error")
	}
	assertTokenError(t, tokenSvc.RevokeToken(context.Background(), nil), modelsystem.ErrTokenRevokeRequestNil.Error())
	assertTokenError(t, tokenSvc.RevokeTokenFamily(context.Background(), "", "tester"), modelsystem.ErrFamilyIDRequired.Error())
	if err := tokenSvc.RevokeTokenFamily(context.Background(), "not-a-uuid", "tester"); err == nil {
		t.Fatalf("expected invalid family id error")
	}
}
