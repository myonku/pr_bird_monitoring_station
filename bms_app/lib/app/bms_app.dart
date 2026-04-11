import 'package:flutter/material.dart';

import 'package:bms_app/app/app_controller.dart';
import 'package:bms_app/auth/auth_controller.dart';
import 'package:bms_app/auth/auth_service.dart';
import 'package:bms_app/data_source/home_data_source.dart';
import 'package:bms_app/data_source/monitoring_repository.dart';
import 'package:bms_app/data_source/records_data_source.dart';
import 'package:bms_app/data_source/stats_data_source.dart';
import 'package:bms_app/models/monitoring_models.dart';
import 'package:bms_app/mock_data/mock_client_repository.dart';
import 'package:bms_app/pages/login_page.dart';
import 'package:bms_app/pages/shell_page.dart';

class BirdMonitoringApp extends StatefulWidget {
  const BirdMonitoringApp({super.key, this.repository});

  final MonitoringRepository? repository;

  @override
  State<BirdMonitoringApp> createState() => _BirdMonitoringAppState();
}

class _BirdMonitoringAppState extends State<BirdMonitoringApp> {
  late final AppController controller;
  late final AuthController authController;
  late final HomeDataSource homeDataSource;
  late final RecordsDataSource recordsDataSource;
  late final StatsDataSource statsDataSource;
  late final Listenable rebuildListenable;
  late final VoidCallback resetIndexOnAuthChange;

  @override
  void initState() {
    super.initState();
    final repository = widget.repository ?? const MockClientRepository();
    controller = AppController();
    authController = AuthController(service: MockAuthService(repository));
    homeDataSource = RepositoryHomeDataSource(repository);
    recordsDataSource = RepositoryRecordsDataSource(repository);
    statsDataSource = RepositoryStatsDataSource(repository);
    resetIndexOnAuthChange = controller.resetIndex;
    authController.addListener(resetIndexOnAuthChange);
    rebuildListenable = Listenable.merge([controller, authController]);
  }

  ThemeData _buildTheme(AppMode mode) {
    final seedColor = mode == AppMode.development
        ? const Color(0xFF0B7A75)
        : const Color(0xFFC97C1D);
    final scheme = ColorScheme.fromSeed(
      seedColor: seedColor,
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
    authController.removeListener(resetIndexOnAuthChange);
    authController.dispose();
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
          theme: _buildTheme(authController.mode),
          home: authController.isAuthenticated
              ? ShellPage(
                  controller: controller,
                  authController: authController,
                  homeDataSource: homeDataSource,
                  recordsDataSource: recordsDataSource,
                  statsDataSource: statsDataSource,
                )
              : LoginPage(authController: authController),
        );
      },
    );
  }
}
