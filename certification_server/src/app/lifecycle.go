package app

import "context"

// HookLifecycle 提供可注入的启动/关闭钩子，便于逐步替换为真实实现。
type HookLifecycle struct {
	OnBoot     func(ctx context.Context) error
	OnShutdown func(ctx context.Context) error
}

// Boot 执行启动钩子。
func (l *HookLifecycle) Boot(ctx context.Context) error {
	if l == nil || l.OnBoot == nil {
		return nil
	}
	return l.OnBoot(ctx)
}

// Shutdown 执行关闭钩子。
func (l *HookLifecycle) Shutdown(ctx context.Context) error {
	if l == nil || l.OnShutdown == nil {
		return nil
	}
	return l.OnShutdown(ctx)
}
