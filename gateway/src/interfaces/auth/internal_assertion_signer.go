package auth

import (
	"context"
	authmodel "gateway/src/models/auth"
)

// IInternalAssertionSigner 定义网关内部断言签发接口。
type IInternalAssertionSigner interface {
	BuildAssertion(ctx context.Context, req *authmodel.InternalAssertionBuildRequest) (string, error)
}
