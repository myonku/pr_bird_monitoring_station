package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	authif "gateway/src/interfaces/auth"
	commsecif "gateway/src/interfaces/commsec"
	authmodel "gateway/src/models/auth"
	commsecmodel "gateway/src/models/commsec"
	modelsystem "gateway/src/models/system"
	"gateway/src/utils"

	"github.com/google/uuid"
)

var _ authif.IInternalAssertionSigner = (*DefaultInternalAssertionSigner)(nil)

// DefaultInternalAssertionSigner 基于本地私钥引用构建并签发内部断言。
type DefaultInternalAssertionSigner struct {
	SecretKeySvc commsecif.ISecretKeyService
	Crypto       *utils.CryptoUtils

	Issuer                    string
	DefaultTTLSeconds         int64
	DefaultSignatureAlgorithm commsecmodel.SignatureAlgorithm
}

func NewDefaultInternalAssertionSigner(secretKeySvc commsecif.ISecretKeyService) *DefaultInternalAssertionSigner {
	return &DefaultInternalAssertionSigner{
		SecretKeySvc:              secretKeySvc,
		Crypto:                    &utils.CryptoUtils{},
		DefaultTTLSeconds:         10,
		DefaultSignatureAlgorithm: commsecmodel.SignatureEd25519,
	}
}

func (s *DefaultInternalAssertionSigner) BuildAssertion(
	ctx context.Context,
	req *authmodel.InternalAssertionBuildRequest,
) (string, error) {
	if s == nil || s.SecretKeySvc == nil || s.Crypto == nil {
		return "", &modelsystem.ErrInternalAssertionSignerRequired
	}
	if req == nil {
		return "", &modelsystem.ErrInternalAssertionBuildRequestNil
	}

	targetService := pickTargetService(req)
	if targetService == "" {
		return "", &modelsystem.ErrTargetServiceRequired
	}

	method := strings.TrimSpace(req.Method)
	if method == "" {
		return "", &modelsystem.ErrGRPCMethodRequired
	}

	privateRef, err := s.SecretKeySvc.GetPrivateKeyRef(ctx)
	if err != nil {
		return "", err
	}
	if privateRef.PrivateKeyRef == "" {
		return "", &modelsystem.ErrLocalPrivateKeyRefNotConfigured
	}
	if privateRef.KeyID == "" {
		return "", &modelsystem.ErrKeyIDRequired
	}

	alg := strings.TrimSpace(string(privateRef.SignatureAlgorithm))
	if alg == "" {
		alg = strings.TrimSpace(string(s.DefaultSignatureAlgorithm))
	}
	if alg == "" {
		alg = string(commsecmodel.SignatureEd25519)
	}

	now := time.Now().Unix()
	ttlSec := s.DefaultTTLSeconds
	if req.TTLSeconds > 0 {
		ttlSec = req.TTLSeconds
	}
	if ttlSec <= 0 {
		ttlSec = 10
	}

	claims := authmodel.InternalAssertionClaims{
		Ver:             "1",
		Iss:             pickIssuer(s.Issuer, privateRef, req),
		Aud:             targetService,
		JTI:             uuid.NewString(),
		IAT:             now,
		EXP:             now + ttlSec,
		TraceID:         req.TraceID,
		RequestID:       req.RequestID,
		Method:          method,
		Path:            req.Path,
		QueryHash:       hashQuery(req.Query),
		BodySHA256:      hashBytes(req.Body),
		SecureChannelID: req.SecureChannelID,
	}

	if req.Identity != nil {
		claims.PrincipalID = req.Identity.PrincipalID
		if claims.PrincipalID == "" {
			claims.PrincipalID = req.Identity.Principal.PrincipalID()
		}
		claims.EntityType = string(req.Identity.EntityType)
		claims.EntityID = req.Identity.EntityID
		if req.Identity.SessionID != uuid.Nil {
			claims.SessionID = req.Identity.SessionID.String()
		}
		if req.Identity.TokenID != uuid.Nil {
			claims.TokenID = req.Identity.TokenID.String()
		}
		if req.Identity.SecureChannelID != uuid.Nil && claims.SecureChannelID == "" {
			claims.SecureChannelID = req.Identity.SecureChannelID.String()
		}
		claims.GatewayID = req.Identity.GatewayID
		if len(req.Identity.Scopes) > 0 {
			claims.Scopes = append(claims.Scopes, req.Identity.Scopes...)
		}
	}

	if req.Grant != nil {
		if claims.PrincipalID == "" {
			claims.PrincipalID = req.Grant.PrincipalID
		}
		if claims.SessionID == "" && req.Grant.SessionID != uuid.Nil {
			claims.SessionID = req.Grant.SessionID.String()
		}
		if claims.TokenID == "" && req.Grant.TokenID != uuid.Nil {
			claims.TokenID = req.Grant.TokenID.String()
		}
		if claims.GatewayID == "" {
			claims.GatewayID = req.Grant.GatewayID
		}
		if claims.SecureChannelID == "" && req.Grant.SecureChannelID != uuid.Nil {
			claims.SecureChannelID = req.Grant.SecureChannelID.String()
		}
		if len(claims.Scopes) == 0 && len(req.Grant.Scopes) > 0 {
			claims.Scopes = append(claims.Scopes, req.Grant.Scopes...)
		}
	}

	if claims.EntityType == "" && claims.PrincipalID != "" {
		parts := strings.SplitN(claims.PrincipalID, ":", 2)
		if len(parts) == 2 {
			claims.EntityType = parts[0]
			if claims.EntityID == "" {
				claims.EntityID = parts[1]
			}
		}
	}

	header := authmodel.InternalAssertionHeader{
		Ver: "1",
		Alg: alg,
		Kid: privateRef.KeyID,
		Typ: "bms-internal+jws",
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("%w: %v", &modelsystem.ErrInternalAssertionMarshalFailed, err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("%w: %v", &modelsystem.ErrInternalAssertionMarshalFailed, err)
	}

	headerSeg := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadSeg := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := headerSeg + "." + payloadSeg

	signatureB64, err := s.Crypto.SignByAlgorithm(alg, []byte(signingInput), []byte(privateRef.PrivateKeyRef))
	if err != nil {
		return "", fmt.Errorf("%w: %v", &modelsystem.ErrInternalAssertionSignFailed, err)
	}

	signatureRaw, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return "", fmt.Errorf("%w: %v", &modelsystem.ErrInternalAssertionSignatureEncodeFailed, err)
	}

	signatureSeg := base64.RawURLEncoding.EncodeToString(signatureRaw)
	return signingInput + "." + signatureSeg, nil
}

func pickTargetService(req *authmodel.InternalAssertionBuildRequest) string {
	if req == nil {
		return ""
	}
	if req.TargetService != "" {
		return req.TargetService
	}
	if req.Grant != nil && req.Grant.TargetService != "" {
		return req.Grant.TargetService
	}
	if req.Identity != nil {
		return req.Identity.TargetService
	}
	return ""
}

func pickIssuer(
	override string,
	privateRef commsecmodel.LocalPrivateKeyRef,
	req *authmodel.InternalAssertionBuildRequest,
) string {
	if override != "" {
		return override
	}
	if entityID := privateRef.Owner.EffectiveEntityID(); entityID != "" {
		return entityID
	}
	if req != nil {
		if req.Grant != nil && req.Grant.GatewayID != "" {
			return req.Grant.GatewayID
		}
		if req.Identity != nil && req.Identity.GatewayID != "" {
			return req.Identity.GatewayID
		}
	}
	return "gateway"
}

func hashBytes(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func hashQuery(query map[string]string) string {
	if len(query) == 0 {
		return ""
	}

	keys := make([]string, 0, len(query))
	for k := range query {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	b := strings.Builder{}
	for _, k := range keys {
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(query[k])
		b.WriteString("\n")
	}

	return hashBytes([]byte(b.String()))
}
