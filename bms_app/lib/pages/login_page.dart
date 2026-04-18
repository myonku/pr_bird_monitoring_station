import 'package:bms_app/models/monitoring_models.dart';
import 'package:flutter/material.dart';

import 'package:bms_app/auth/auth_controller.dart';
import 'package:bms_app/pages/register_page.dart';

class LoginPage extends StatefulWidget {
  const LoginPage({super.key, required this.authController});

  final AuthController authController;

  @override
  State<LoginPage> createState() => _LoginPageState();
}

class _LoginPageState extends State<LoginPage> {
  final TextEditingController _identifierController = TextEditingController(
    text: 'demo_user',
  );
  final TextEditingController _passwordController = TextEditingController(
    text: 'bird123456',
  );

  @override
  void dispose() {
    _identifierController.dispose();
    _passwordController.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    await widget.authController.signIn(
      identifier: _identifierController.text,
      password: _passwordController.text,
    );
  }

  Future<void> _openRegisterPage() async {
    final registeredUsername = await Navigator.of(context).push<String>(
      MaterialPageRoute(
        builder: (_) => RegisterPage(authController: widget.authController),
      ),
    );

    if (!mounted || registeredUsername == null || registeredUsername.isEmpty) {
      return;
    }

    setState(() {
      _identifierController.text = registeredUsername;
      _passwordController.clear();
    });
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('注册成功，请使用新账号登录')),
    );
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Scaffold(
      body: Container(
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
            colors: [Color(0xFFF6FAFD), Color(0xFFEAF5F3)],
          ),
        ),
        child: SafeArea(
          child: Center(
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(24),
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 440),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    _HeroBanner(mode: widget.authController.mode),
                    const SizedBox(height: 24),
                    Card(
                      child: Padding(
                        padding: const EdgeInsets.all(24),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text('登录系统', style: theme.textTheme.headlineMedium),
                            const SizedBox(height: 8),
                            Text(
                              '认证模块与页面已分离，后续可直接替换为真实后端实现。',
                              style: theme.textTheme.bodyMedium?.copyWith(
                                color: Colors.black54,
                              ),
                            ),
                            const SizedBox(height: 20),
                            _ModeSelector(
                              mode: widget.authController.mode,
                              onChanged: widget.authController.switchMode,
                            ),
                            const SizedBox(height: 20),
                            TextField(
                              controller: _identifierController,
                              decoration: const InputDecoration(
                                labelText: '用户名 / 邮箱 / 手机号',
                                hintText: '请输入任一登录标识',
                                prefixIcon: Icon(Icons.person_outline),
                              ),
                            ),
                            const SizedBox(height: 16),
                            TextField(
                              controller: _passwordController,
                              obscureText: true,
                              decoration: const InputDecoration(
                                labelText: '密码',
                                hintText: '请输入密码',
                                prefixIcon: Icon(Icons.lock_outline),
                              ),
                            ),
                            const SizedBox(height: 20),
                            SizedBox(
                              width: double.infinity,
                              height: 52,
                              child: FilledButton.icon(
                                onPressed: _submit,
                                icon: const Icon(Icons.login),
                                label: Text(
                                  widget.authController.mode ==
                                          AppMode.development
                                      ? '登录并保存凭证'
                                      : '登录进入演示模式',
                                ),
                              ),
                            ),
                            const SizedBox(height: 12),
                            Center(
                              child: TextButton.icon(
                                onPressed: _openRegisterPage,
                                icon: const Icon(Icons.person_add_alt_1),
                                label: const Text('没有账号，去注册'),
                              ),
                            ),
                            const SizedBox(height: 8),
                            Text(
                              widget.authController.mode == AppMode.development
                                  ? 'development 模式下会生成 mock access / refresh token，并单独拉取用户资料。'
                                  : 'no-auth 模式下仅进入业务页面，不保存任何凭证。',
                              style: theme.textTheme.bodySmall?.copyWith(
                                color: Colors.black54,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class _HeroBanner extends StatelessWidget {
  const _HeroBanner({required this.mode});

  final AppMode mode;

  @override
  Widget build(BuildContext context) {
    final isDevelopment = mode == AppMode.development;
    final colors = isDevelopment
        ? const [Color(0xFF0B7A75), Color(0xFF125D98)]
        : const [Color(0xFFC97C1D), Color(0xFFE09F3E)];

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(24),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(28),
        gradient: LinearGradient(colors: colors),
        boxShadow: const [
          BoxShadow(
            color: Color(0x20000000),
            blurRadius: 24,
            offset: Offset(0, 12),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            width: 54,
            height: 54,
            decoration: BoxDecoration(
              color: Colors.white.withValues(alpha: 0.18),
              borderRadius: BorderRadius.circular(18),
            ),
            child: const Icon(Icons.radar, color: Colors.white, size: 30),
          ),
          const SizedBox(height: 18),
          Text(
            '鸟类监测系统',
            style: Theme.of(
              context,
            ).textTheme.headlineMedium?.copyWith(color: Colors.white),
          ),
          const SizedBox(height: 8),
          Text(
            '客户端展示骨架 · ${mode.displayName}',
            style: Theme.of(context).textTheme.bodyMedium?.copyWith(
              color: Colors.white.withValues(alpha: 0.9),
            ),
          ),
        ],
      ),
    );
  }
}

class _ModeSelector extends StatelessWidget {
  const _ModeSelector({required this.mode, required this.onChanged});

  final AppMode mode;
  final ValueChanged<AppMode> onChanged;

  @override
  Widget build(BuildContext context) {
    return Wrap(
      spacing: 12,
      runSpacing: 12,
      children: [
        ChoiceChip(
          label: const Text('development'),
          selected: mode == AppMode.development,
          onSelected: (_) => onChanged(AppMode.development),
        ),
        ChoiceChip(
          label: const Text('no-auth'),
          selected: mode == AppMode.noAuth,
          onSelected: (_) => onChanged(AppMode.noAuth),
        ),
      ],
    );
  }
}
