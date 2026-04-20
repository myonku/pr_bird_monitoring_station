import 'package:flutter/material.dart';

import 'package:bms_app/app/app_controller.dart';
import 'package:bms_app/controller/controller.dart';
import 'package:bms_app/credential_manager/credential_manager.dart';
import 'package:bms_app/storage/storage.dart';
import 'package:bms_app/transport/transport_client.dart';
import 'package:bms_app/transport/mock_client.dart';
import 'package:bms_app/models/common.dart';
import 'package:bms_app/pages/login/login_page.dart';
import 'package:bms_app/pages/shell/shell_page.dart';
import 'package:bms_app/mock_repo/mock_repository.dart';

class BirdMonitoringApp extends StatefulWidget {
  const BirdMonitoringApp({
    super.key,
    this.client,
    this.sessionStore,
    this.initialMode = AppMode.development,
    this.defaultUser = const AppUser(
      name: '测试用户',
      role: '系统演示账号',
      phone: '138-0000-0000',
      avatarB64: kSampleBirdImageB64,
      userId: '7a4a7c0c-6b12-4d5f-9a8f-7b2a12d02f19',
      username: 'demo_user',
      displayName: '测试用户',
      email: 'demo_user@example.com',
    ),
  });

  final MonitoringClient? client;
  final AuthSessionStore? sessionStore;
  final AppMode initialMode;
  final AppUser defaultUser;

  @override
  State<BirdMonitoringApp> createState() => _BirdMonitoringAppState();
}

class _BirdMonitoringAppState extends State<BirdMonitoringApp> {
  late final AppController controller;
  late final MonitoringController monitoringController;
  late final Listenable rebuildListenable;
  late final VoidCallback resetIndexOnAuthChange;

  @override
  void initState() {
    super.initState();
    final client = widget.client ?? MockMonitoringClient();
    final credentials = MonitoringCredentialManager(
      initialMode: widget.initialMode,
      sessionStore: widget.sessionStore,
    );
    controller = AppController();
    monitoringController = MonitoringController(
      client: client,
      credentials: credentials,
      defaultUser: widget.defaultUser,
    );
    resetIndexOnAuthChange = controller.resetIndex;
    monitoringController.addListener(resetIndexOnAuthChange);
    rebuildListenable = Listenable.merge([controller, monitoringController]);
  }

  ThemeData _buildTheme(AppMode mode) {
    final scheme = ColorScheme.fromSeed(
      seedColor: mode.seedColor,
      brightness: Brightness.light,
    );

    return ThemeData(
      useMaterial3: true,
      colorScheme: scheme,
      scaffoldBackgroundColor: const Color(0xFFF4F7FB),
      appBarTheme: const AppBarTheme(centerTitle: false),
      navigationBarTheme: NavigationBarThemeData(
        backgroundColor: Colors.white,
        indicatorColor: scheme.primaryContainer,
        labelTextStyle: WidgetStatePropertyAll(
          TextStyle(
            fontSize: 12,
            fontWeight: FontWeight.w600,
            color: scheme.primary,
          ),
        ),
      ),
      cardTheme: CardThemeData(
        elevation: 0,
        color: Colors.white,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(24)),
      ),
      textTheme: const TextTheme(
        headlineLarge: TextStyle(
          fontSize: 32,
          fontWeight: FontWeight.w800,
          height: 1.1,
        ),
        headlineMedium: TextStyle(
          fontSize: 24,
          fontWeight: FontWeight.w700,
          height: 1.15,
        ),
        titleLarge: TextStyle(fontSize: 20, fontWeight: FontWeight.w700),
        titleMedium: TextStyle(fontSize: 16, fontWeight: FontWeight.w600),
        bodyLarge: TextStyle(fontSize: 15, height: 1.45),
        bodyMedium: TextStyle(fontSize: 14, height: 1.45),
      ),
    );
  }

  @override
  void dispose() {
    monitoringController.removeListener(resetIndexOnAuthChange);
    monitoringController.dispose();
    controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: rebuildListenable,
      builder: (context, _) {
        return MaterialApp(
          debugShowCheckedModeBanner: false,
          title: '鸟类监测系统',
          theme: _buildTheme(monitoringController.mode),
          home: monitoringController.isAuthenticated
              ? ShellPage(
                  controller: controller,
                  monitoringController: monitoringController,
                )
              : LoginPage(monitoringController: monitoringController),
        );
      },
    );
  }
}
