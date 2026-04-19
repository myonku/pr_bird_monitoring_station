// This is a basic Flutter widget test.
//
// To perform an interaction with a widget in your test, use the WidgetTester
// utility in the flutter_test package. For example, you can send tap and scroll
// gestures. You can also use WidgetTester to find child widgets in the widget
// tree, read text, and verify that the values of widget properties are correct.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:bms_app/app/bms_app.dart';
import 'package:bms_app/credential_manager/credential_manager.dart';
import 'package:bms_app/data_source/repository.dart';
import 'package:bms_app/data_source/monitoring_repository.dart';
import 'package:bms_app/models/common.dart';
import 'package:bms_app/pages/stats/stats_page.dart';
import 'package:bms_app/transport/mock_client.dart';

MonitoringRepository _buildNoAuthRepository() {
  return ClientBackedMonitoringRepository(
    client: MockMonitoringClient(),
    credentials: MonitoringCredentialManager(initialMode: AppMode.noAuth),
    defaultUser: const AppUser(
      name: '测试用户',
      role: '系统演示账号',
      phone: '138-0000-0000',
      avatarSeed: 7,
      userId: '7a4a7c0c-6b12-4d5f-9a8f-7b2a12d02f19',
      username: 'demo_user',
      displayName: '测试用户',
      email: 'demo_user@example.com',
    ),
  );
}

void main() {
  testWidgets('shows login screen and can enter main shell', (
    WidgetTester tester,
  ) async {
    await tester.pumpWidget(const BirdMonitoringApp());

    expect(find.text('鸟类监测系统'), findsOneWidget);
    expect(find.text('登录系统'), findsOneWidget);
    expect(find.textContaining('测试模式'), findsWidgets);

    await tester.enterText(find.byType(TextField).first, 'tester');
    await tester.enterText(find.byType(TextField).at(1), 'secret');
    await tester.tap(find.text('登录并进入系统'));
    await tester.pumpAndSettle();

    expect(find.text('首页'), findsWidgets);
    expect(find.text('记录'), findsWidgets);
    expect(find.text('统计'), findsWidgets);
    expect(find.text('我的'), findsWidgets);
  });

  testWidgets('renders the home screen on a narrow viewport without overflow', (
    WidgetTester tester,
  ) async {
    tester.view.physicalSize = const Size(360, 800);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    await tester.pumpWidget(const BirdMonitoringApp());
    await tester.enterText(find.byType(TextField).first, 'tester');
    await tester.enterText(find.byType(TextField).at(1), 'secret');
    await tester.ensureVisible(find.text('登录并进入系统'));
    await tester.tap(find.text('登录并进入系统'));
    await tester.pumpAndSettle();

    expect(find.text('首页'), findsWidgets);
    expect(tester.takeException(), isNull);
  });

  testWidgets('renders the weekly trend chart with visible size', (
    WidgetTester tester,
  ) async {
    final repository = _buildNoAuthRepository();
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: StatsPage(repository: repository),
        ),
      ),
    );
    await tester.pumpAndSettle();

    final customPaints = find.byType(CustomPaint);
    expect(customPaints, findsWidgets);

    final weeklyTrendSize = tester.getSize(customPaints.first);
    expect(weeklyTrendSize.width, greaterThan(0));
    expect(weeklyTrendSize.height, greaterThan(0));
  });
}
