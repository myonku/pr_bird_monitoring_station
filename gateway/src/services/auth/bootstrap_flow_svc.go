package auth

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	authif "gateway/src/interfaces/auth"
	commsecif "gateway/src/interfaces/commsec"
	authmodel "gateway/src/models/auth"
	modelsystem "gateway/src/models/system"
	"gateway/src/utils"
)

var _ authif.IBootstrapFlowCoordinator = (*BootstrapFlowCoordinator)(nil)

// BootstrapFlowCoordinator 负责网关启动阶段 bootstrap 编排。
type BootstrapFlowCoordinator struct {
	BootstrapClient authif.IBootstrapClient
	KeyService      commsecif.ISecretKeyService

	Crypto *utils.CryptoUtils

	mu        sync.RWMutex
	lastReady *authmodel.BootstrapAuthResult
}

func (c *BootstrapFlowCoordinator) EnsureReady(
	ctx context.Context,
	req *authmodel.BootstrapEnsureReadyRequest,
) (*authmodel.BootstrapAuthResult, error) {
	if c == nil || c.BootstrapClient == nil {
		return nil, &modelsystem.ErrBootstrapClientRequired
	}
	if req == nil || req.ChallengeRequest == nil {
		return nil, &modelsystem.ErrChallengeRequestNil
	}
	if c.Crypto == nil {
		c.Crypto = &utils.CryptoUtils{}
	}

	stage, err := c.BootstrapClient.GetBootstrapStage(ctx)
	if err != nil {
		return nil, err
	}
	if stage == authmodel.BootstrapStageReady {
		if cached := c.snapshotReady(); cached != nil {
			return cached, nil
		}
	}

	challenge, err := c.BootstrapClient.InitChallenge(ctx, req.ChallengeRequest)
	if err != nil {
		return nil, err
	}

	signed, err := c.signChallenge(ctx, req, challenge)
	if err != nil {
		return nil, err
	}

	result, err := c.BootstrapClient.AuthenticateBootstrap(ctx, &authmodel.BootstrapAuthRequest{
		Challenge:              *challenge,
		Signed:                 *signed,
		Role:                   req.Role,
		Scopes:                 append([]string(nil), req.Scopes...),
		RequireDownstreamToken: req.RequireDownstreamToken,
	})
	if err != nil {
		return nil, err
	}

	c.setReady(result)
	return result, nil
}

func (c *BootstrapFlowCoordinator) signChallenge(
	ctx context.Context,
	req *authmodel.BootstrapEnsureReadyRequest,
	challenge *authmodel.ChallengePayload,
) (*authmodel.SignedChallengeResponse, error) {
	if req.Signer != nil {
		return req.Signer(ctx, challenge)
	}
	if c.KeyService == nil {
		return nil, &modelsystem.ErrChallengeSignerRequired
	}
	privateRef, err := c.KeyService.GetPrivateKeyRef(ctx)
	if err != nil {
		return nil, err
	}
	publicKey, err := c.KeyService.GetPublicKey(ctx)
	if err != nil {
		return nil, err
	}
	sigAlg, err := c.Crypto.DetectSignatureAlgorithmFromPublicPEM([]byte(publicKey.PublicKeyPEM))
	if err != nil {
		return nil, err
	}

	payload := []byte(buildBootstrapSignaturePayload(challenge))

	sig, err := c.Crypto.SignByAlgorithm(string(sigAlg), payload, []byte(privateRef.PrivateKeyRef))
	if err != nil {
		return nil, fmt.Errorf("sign challenge failed: %w", err)
	}

	return &authmodel.SignedChallengeResponse{
		ChallengeID:        challenge.ChallengeID,
		KeyID:              privateRef.KeyID,
		SignatureAlgorithm: sigAlg,
		Signature:          sig,
		SignedAt:           time.Now(),
	}, nil
}

func (c *BootstrapFlowCoordinator) snapshotReady() *authmodel.BootstrapAuthResult {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return cloneBootstrapResult(c.lastReady)
}

func (c *BootstrapFlowCoordinator) setReady(result *authmodel.BootstrapAuthResult) {
	if result == nil {
		return
	}
	c.mu.Lock()
	c.lastReady = cloneBootstrapResult(result)
	c.mu.Unlock()
}

func cloneBootstrapResult(in *authmodel.BootstrapAuthResult) *authmodel.BootstrapAuthResult {
	if in == nil {
		return nil
	}
	out := *in
	if in.Identity != nil {
		identity := *in.Identity
		identity.Scopes = append([]string(nil), in.Identity.Scopes...)
		out.Identity = &identity
	}
	if in.Session != nil {
		session := *in.Session
		session.ScopeSnapshot = append([]string(nil), in.Session.ScopeSnapshot...)
		out.Session = &session
	}
	out.Tokens = authmodel.TokenBundle{
		AccessToken:     cloneIssuedToken(in.Tokens.AccessToken),
		RefreshToken:    cloneIssuedToken(in.Tokens.RefreshToken),
		DownstreamToken: cloneIssuedToken(in.Tokens.DownstreamToken),
	}
	return &out
}

func cloneIssuedToken(in *authmodel.IssuedToken) *authmodel.IssuedToken {
	if in == nil {
		return nil
	}
	out := *in
	out.Claims.Scopes = append([]string(nil), in.Claims.Scopes...)
	return &out
}

func buildBootstrapSignaturePayload(challenge *authmodel.ChallengePayload) string {
	if challenge == nil {
		return ""
	}
	parts := []string{
		challenge.ChallengeID.String(),
		challenge.Issuer,
		challenge.Audience,
		string(challenge.EntityType),
		challenge.EntityID,
		challenge.KeyID,
		challenge.Nonce,
		challenge.IssuedAt.UTC().Format(time.RFC3339Nano),
		challenge.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}
	return strings.Join(parts, "|")
}
