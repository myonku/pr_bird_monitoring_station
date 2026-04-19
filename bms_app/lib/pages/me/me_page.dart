import 'package:flutter/material.dart';

import 'package:bms_app/controller/controller.dart';
import 'package:bms_app/models/common.dart';
import 'package:bms_app/pages/widgets/info_card.dart';

class MePage extends StatefulWidget {
  const MePage({super.key, required this.monitoringController});

  final MonitoringController monitoringController;

  @override
  State<MePage> createState() => _MePageState();
}

class _MePageState extends State<MePage> {
  Future<AppUser?>? _profileFuture;

  @override
  void initState() {
    super.initState();
    _profileFuture = widget.monitoringController.loadCurrentUserProfile();
  }

  Future<void> _reloadProfile() async {
    final future = widget.monitoringController.loadCurrentUserProfile();
    setState(() {
      _profileFuture = future;
    });
    await future;
  }

  @override
  Widget build(BuildContext context) {
    final mode = widget.monitoringController.mode;

    return FutureBuilder<AppUser?>(
      future: _profileFuture,
      builder: (context, snapshot) {
        if (snapshot.connectionState == ConnectionState.waiting) {
          return ListView(
            padding: const EdgeInsets.all(20),
            children: [
              Container(
                padding: const EdgeInsets.all(20),
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(28),
                  gradient: LinearGradient(
                    colors: mode.bannerColors,
                    begin: Alignment.topLeft,
                    end: Alignment.bottomRight,
                  ),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      '正在加载用户资料',
                      style: Theme.of(
                        context,
                      ).textTheme.titleLarge?.copyWith(color: Colors.white),
                    ),
                    const SizedBox(height: 8),
                    Text(
                      '登录后会在我的页面单独拉取个人信息。',
                      style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                        color: Colors.white.withValues(alpha: 0.9),
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 24),
              const Center(child: CircularProgressIndicator()),
            ],
          );
        }

        if (snapshot.hasError) {
          return ListView(
            padding: const EdgeInsets.all(20),
            children: [
              Container(
                padding: const EdgeInsets.all(20),
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(28),
                  gradient: LinearGradient(
                    colors: mode.bannerColors,
                    begin: Alignment.topLeft,
                    end: Alignment.bottomRight,
                  ),
                ),
                child: Text(
                  '用户资料加载失败',
                  style: Theme.of(
                    context,
                  ).textTheme.titleLarge?.copyWith(color: Colors.white),
                ),
              ),
              const SizedBox(height: 18),
              InfoCard(
                title: '错误信息',
                children: [InfoRow(label: '原因', value: '${snapshot.error}')],
              ),
              const SizedBox(height: 18),
              SizedBox(
                height: 52,
                child: FilledButton.icon(
                  onPressed: _reloadProfile,
                  icon: const Icon(Icons.refresh),
                  label: const Text('重试加载'),
                ),
              ),
              const SizedBox(height: 12),
              SizedBox(
                height: 52,
                child: OutlinedButton.icon(
                  onPressed: widget.monitoringController.signOut,
                  icon: const Icon(Icons.logout),
                  label: const Text('退出登录'),
                ),
              ),
            ],
          );
        }

        final user = snapshot.data ?? widget.monitoringController.activeUser;
        final username = user.username?.trim().isNotEmpty == true
            ? user.username!.trim()
            : user.name;
        final email = user.email?.trim().isNotEmpty == true
            ? user.email!.trim()
            : '';
        final headerIdentity = email.isNotEmpty ? email : username;

        return ListView(
          padding: const EdgeInsets.all(20),
          children: [
            Container(
              padding: const EdgeInsets.all(20),
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(28),
                gradient: LinearGradient(
                  colors: mode.bannerColors,
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
                          style: Theme.of(context).textTheme.bodyMedium
                              ?.copyWith(
                                color: Colors.white.withValues(alpha: 0.9),
                              ),
                        ),
                        const SizedBox(height: 8),
                        Text(
                          '$headerIdentity · ${mode.displayName}',
                          style: Theme.of(context).textTheme.bodySmall
                              ?.copyWith(
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
            InfoCard(
              title: '认证信息',
              children: [
                InfoRow(
                  label: '登录状态',
                  value: widget.monitoringController.statusLabel,
                ),
                InfoRow(label: '当前模式', value: mode.displayName),
                InfoRow(
                  label: '凭证策略',
                  value: widget.monitoringController.credentialPolicyLabel,
                ),
                InfoRow(
                  label: '凭证存储',
                  value: widget.monitoringController.credentialStorageLabel,
                ),
                InfoRow(
                  label: '登录时间',
                  value: widget.monitoringController.signedInAt == null
                      ? '-'
                      : '${widget.monitoringController.signedInAt!.year}-${widget.monitoringController.signedInAt!.month.toString().padLeft(2, '0')}-${widget.monitoringController.signedInAt!.day.toString().padLeft(2, '0')}',
                ),
              ],
            ),
            const SizedBox(height: 12),
            InfoCard(
              title: '用户信息',
              children: [
                InfoRow(label: '用户名', value: username),
                InfoRow(label: '邮箱', value: email.isEmpty ? '-' : email),
                InfoRow(label: '手机号', value: user.phone),
              ],
            ),
            const SizedBox(height: 18),
            SizedBox(
              height: 52,
              child: FilledButton.icon(
                onPressed: widget.monitoringController.signOut,
                icon: const Icon(Icons.logout),
                label: const Text('退出登录'),
              ),
            ),
          ],
        );
      },
    );
  }
}
