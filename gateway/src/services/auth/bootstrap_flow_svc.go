package auth

import (
	"context"
	"encoding/json"
	"fmt"
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
		now := time.Now()
		return &authmodel.BootstrapAuthResult{
			Stage:     authmodel.BootstrapStageReady,
			IssuedAt:  now,
			ExpiresAt: now,
		}, nil
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

	payload, err := json.Marshal(struct {
		ChallengeID string               `json:"challenge_id"`
		EntityType  authmodel.EntityType `json:"entity_type"`
		EntityID    string               `json:"entity_id"`
		KeyID       string               `json:"key_id"`
		Nonce       string               `json:"nonce"`
		IssuedAt    int64                `json:"issued_at"`
		ExpiresAt   int64                `json:"expires_at"`
	}{
		ChallengeID: challenge.ChallengeID.String(),
		EntityType:  challenge.EntityType,
		EntityID:    challenge.EntityID,
		KeyID:       challenge.KeyID,
		Nonce:       challenge.Nonce,
		IssuedAt:    challenge.IssuedAt.Unix(),
		ExpiresAt:   challenge.ExpiresAt.Unix(),
	})
	if err != nil {
		return nil, err
	}

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
