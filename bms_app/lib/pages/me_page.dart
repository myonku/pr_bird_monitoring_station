import 'package:flutter/material.dart';

import 'package:bms_app/auth/auth_controller.dart';
import 'package:bms_app/models/monitoring_models.dart';

class MePage extends StatelessWidget {
  const MePage({super.key, required this.authController});

  final AuthController authController;

  @override
  Widget build(BuildContext context) {
    final user = authController.activeUser;

    return ListView(
      padding: const EdgeInsets.all(20),
      children: [
        Container(
          padding: const EdgeInsets.all(20),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(28),
            gradient: const LinearGradient(
              colors: [Color(0xFF0B7A75), Color(0xFF125D98)],
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
            ),
          ),
          child: Row(
            children: [
              CircleAvatar(
                radius: 34,
                backgroundColor: Colors.white.withValues(alpha: 0.18),
                child: Text(
                  user.name.isNotEmpty ? user.name.substring(0, 1) : 'B',
                  style: const TextStyle(
                    color: Colors.white,
                    fontSize: 24,
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      user.name,
                      style: Theme.of(
                        context,
                      ).textTheme.titleLarge?.copyWith(color: Colors.white),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      user.role,
                      style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                        color: Colors.white.withValues(alpha: 0.9),
                      ),
                    ),
                    const SizedBox(height: 8),
                    Text(
                      '${user.station} · ${authController.mode.displayName}',
                      style: Theme.of(context).textTheme.bodySmall?.copyWith(
                        color: Colors.white.withValues(alpha: 0.85),
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 18),
        _InfoCard(
          title: '认证信息',
          children: [
            _InfoRow(label: '登录状态', value: authController.statusLabel),
            _InfoRow(label: '当前模式', value: authController.mode.displayName),
            _InfoRow(
              label: '凭证策略',
              value: authController.credentialPolicyLabel,
            ),
            _InfoRow(
              label: '凭证存储',
              value: authController.credentialStorageLabel,
            ),
            _InfoRow(
              label: '登录时间',
              value: authController.signedInAt == null
                  ? '-'
                  : '${authController.signedInAt!.year}-${authController.signedInAt!.month.toString().padLeft(2, '0')}-${authController.signedInAt!.day.toString().padLeft(2, '0')}',
            ),
          ],
        ),
        const SizedBox(height: 12),
        _InfoCard(
          title: '用户信息',
          children: [
            _InfoRow(label: '手机号', value: user.phone),
            _InfoRow(label: '站点', value: user.station),
          ],
        ),
        const SizedBox(height: 18),
        SizedBox(
          height: 52,
          child: FilledButton.icon(
            onPressed: authController.signOut,
            icon: const Icon(Icons.logout),
            label: const Text('退出登录'),
          ),
        ),
      ],
    );
  }
}

class _InfoCard extends StatelessWidget {
  const _InfoCard({required this.title, required this.children});

  final String title;
  final List<Widget> children;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(24),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(title, style: Theme.of(context).textTheme.titleLarge),
          const SizedBox(height: 12),
          ...children,
        ],
      ),
    );
  }
}

class _InfoRow extends StatelessWidget {
  const _InfoRow({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 88,
            child: Text(
              label,
              style: Theme.of(
                context,
              ).textTheme.bodyMedium?.copyWith(color: Colors.black54),
            ),
          ),
          Expanded(
            child: Text(value, style: Theme.of(context).textTheme.bodyMedium),
          ),
        ],
      ),
    );
  }
}
