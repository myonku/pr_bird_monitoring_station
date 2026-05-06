package orchestration

import (
	"log"
	"strings"
	"sync"
	"time"

	commonif "certification_server/src/iface/common"
	iface "certification_server/src/iface/orchestration"
	authmodel "certification_server/src/models/auth"

	"github.com/google/uuid"
)

const defaultSessionTTL = 7 * 24 * time.Hour

var _ iface.IAuthRequestOrchestrator = (*AuthRequestOrchestratorService)(nil)

// AuthRequestOrchestratorService 是认证中心请求编排的最小实现骨架。
type AuthRequestOrchestratorService struct {
	keyManager     commonif.ISecretKeyManager
	sessionManager commonif.ISessionManager
	tokenManager   commonif.ITokenManager
	userCredential commonif.IUserCredentialManager

	mu              sync.RWMutex
	bootstrapByID   map[uuid.UUID]authmodel.ChallengePayload
	defaultAudience string
}

// NewAuthRequestOrchestratorService 创建最小可编译编排服务骨架。
func NewAuthRequestOrchestratorService() *AuthRequestOrchestratorService {
	return NewAuthRequestOrchestratorServiceWithDeps(nil, nil, nil, nil)
}

func NewAuthRequestOrchestratorServiceWithDeps(
	keyManager commonif.ISecretKeyManager,
	sessionManager commonif.ISessionManager,
	tokenManager commonif.ITokenManager,
	userCredential commonif.IUserCredentialManager,
) *AuthRequestOrchestratorService {
	return &AuthRequestOrchestratorService{
		keyManager:      keyManager,
		sessionManager:  sessionManager,
		tokenManager:    tokenManager,
		userCredential:  userCredential,
		bootstrapByID:   make(map[uuid.UUID]authmodel.ChallengePayload),
		defaultAudience: "certification_server",
	}
}

func logAuthRequestObservation(interfaceName string) {
	log.Printf("[observe] service=certification_server interface=%s status=request", interfaceName)
}

func logAuthRequestResult(interfaceName string, success bool, detail string) {
	status := "failure"
	if success {
		status = "success"
	}
	if strings.TrimSpace(detail) != "" {
		log.Printf("[observe] service=certification_server interface=%s status=%s detail=%s", interfaceName, status, detail)
		return
	}
	log.Printf("[observe] service=certification_server interface=%s status=%s", interfaceName, status)
}
