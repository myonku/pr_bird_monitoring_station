package orchestration

import (
	"sync"

	commonif "certification_server/src/iface/common"
	iface "certification_server/src/iface/orchestration"
	authmodel "certification_server/src/models/auth"

	"github.com/google/uuid"
)

var _ iface.IAuthRequestOrchestrator = (*AuthRequestOrchestratorService)(nil)

// AuthRequestOrchestratorService 是认证中心请求编排的最小实现骨架。
type AuthRequestOrchestratorService struct {
	keyManager     commonif.IKeyManager
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
	keyManager commonif.IKeyManager,
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
