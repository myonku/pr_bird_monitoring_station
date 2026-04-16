package orchestration_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	commonif "certification_server/src/iface/common"
	authmodel "certification_server/src/models/auth"
	commsecmodel "certification_server/src/models/commsec"
)

type stubKeyManager struct {
	lookupReq    *commsecmodel.PublicKeyLookupRequest
	lookupResult commsecmodel.PublicKeyLookupResult
	lookupErr    error
}

func (s *stubKeyManager) GetPublicKey(context.Context) (commsecmodel.ServicePublicKeyRecord, error) {
	return commsecmodel.ServicePublicKeyRecord{}, nil
}

func (s *stubKeyManager) GetPrivateKeyRef(context.Context) (commsecmodel.LocalPrivateKeyRef, error) {
	return commsecmodel.LocalPrivateKeyRef{}, nil
}

func (s *stubKeyManager) LookupPublicKey(_ context.Context, req *commsecmodel.PublicKeyLookupRequest) (commsecmodel.PublicKeyLookupResult, error) {
	s.lookupReq = req
	if s.lookupErr != nil {
		return commsecmodel.PublicKeyLookupResult{}, s.lookupErr
	}
	return s.lookupResult, nil
}

type stubSessionManager struct {
	createReq *commonif.SessionIssueRequest
	session   *authmodel.Session
	createErr error
}

func (s *stubSessionManager) CreateSession(_ context.Context, req *commonif.SessionIssueRequest) (*authmodel.Session, error) {
	s.createReq = req
	if s.createErr != nil {
		return nil, s.createErr
	}
	if s.session != nil {
		return s.session, nil
	}
	return &authmodel.Session{}, nil
}

func (s *stubSessionManager) GetSession(context.Context, string) (*authmodel.Session, error) {
	return nil, nil
}

func (s *stubSessionManager) TouchSession(context.Context, string, authmodel.SessionTouchMeta) error {
	return nil
}

func (s *stubSessionManager) ValidateSession(context.Context, *commonif.SessionValidateRequest) (*authmodel.Session, error) {
	return nil, nil
}

func (s *stubSessionManager) RevokeSession(context.Context, *commonif.SessionRevokeRequest) error {
	return nil
}

func (s *stubSessionManager) RevokePrincipalSessions(context.Context, string, string, string) error {
	return nil
}

type stubTokenManager struct {
	issueBundleReq  *commonif.TokenIssueRequest
	issueBundleSess *authmodel.Session
	bundle          *authmodel.TokenBundle
	issueBundleErr  error
	issueTokenReq   *commonif.TokenIssueRequest
	issuedToken     *authmodel.IssuedToken
	issueTokenErr   error
	revokeReq       *commonif.TokenRevokeRequest
	revokeFamilyID  string
	revokeFamilyBy  string
}

func (s *stubTokenManager) IssueToken(_ context.Context, req *commonif.TokenIssueRequest) (*authmodel.IssuedToken, error) {
	s.issueTokenReq = req
	if s.issueTokenErr != nil {
		return nil, s.issueTokenErr
	}
	if s.issuedToken != nil {
		return s.issuedToken, nil
	}
	return &authmodel.IssuedToken{}, nil
}

func (s *stubTokenManager) IssueTokenBundle(_ context.Context, session *authmodel.Session, req *commonif.TokenIssueRequest) (*authmodel.TokenBundle, error) {
	s.issueBundleSess = session
	s.issueBundleReq = req
	if s.issueBundleErr != nil {
		return nil, s.issueBundleErr
	}
	if s.bundle != nil {
		return s.bundle, nil
	}
	return &authmodel.TokenBundle{}, nil
}

func (s *stubTokenManager) RefreshTokenBundle(context.Context, *commonif.TokenRefreshRequest) (*authmodel.TokenBundle, error) {
	return nil, nil
}

func (s *stubTokenManager) VerifyToken(context.Context, *commonif.TokenVerifyRequest) (*authmodel.TokenVerificationResult, error) {
	return nil, nil
}

func (s *stubTokenManager) RevokeToken(_ context.Context, req *commonif.TokenRevokeRequest) error {
	s.revokeReq = req
	return nil
}

func (s *stubTokenManager) RevokeTokenFamily(_ context.Context, familyID string, revokedBy string) error {
	s.revokeFamilyID = familyID
	s.revokeFamilyBy = revokedBy
	return nil
}

func assertOrchestratorError(t *testing.T, err error, expected string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error %q, got nil", expected)
	}
	if err.Error() != expected {
		t.Fatalf("expected error %q, got %v", expected, err)
	}
}

func writeOrchestratorEd25519KeyPair(t *testing.T, dir string) {
	t.Helper()
	publicPEM, privatePEM := writeEd25519KeyMaterial(t)
	if err := os.WriteFile(filepath.Join(dir, "public.pem"), []byte(publicPEM), 0o644); err != nil {
		t.Fatalf("write public pem: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "private.pem"), []byte(privatePEM), 0o600); err != nil {
		t.Fatalf("write private pem: %v", err)
	}
}
