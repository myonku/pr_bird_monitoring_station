// This is a basic Flutter widget test.
//
// To perform an interaction with a widget in your test, use the WidgetTester
// utility in the flutter_test package. For example, you can send tap and scroll
// gestures. You can also use WidgetTester to find child widgets in the widget
// tree, read text, and verify that the values of widget properties are correct.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:bms_app/app/bms_app.dart';
import 'package:bms_app/data_source/records_data_source.dart';
import 'package:bms_app/data_source/stats_data_source.dart';
import 'package:bms_app/mock_data/mock_client_repository.dart';
import 'package:bms_app/pages/stats_page.dart';

void main() {
  testWidgets('shows login screen and can enter main shell', (
    WidgetTester tester,
  ) async {
    await tester.pumpWidget(const BirdMonitoringApp());

    expect(find.text('鸟类监测系统'), findsOneWidget);
    expect(find.text('登录系统'), findsOneWidget);
    expect(find.text('development'), findsOneWidget);

    await tester.enterText(find.byType(TextField).first, 'tester');
    await tester.enterText(find.byType(TextField).at(1), 'secret');
    await tester.tap(find.text('登录并保存会话'));
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
    await tester.ensureVisible(find.text('登录并保存会话'));
    await tester.tap(find.text('登录并保存会话'));
    await tester.pumpAndSettle();

    expect(find.text('首页'), findsWidgets);
    expect(tester.takeException(), isNull);
  });

  testWidgets('renders the weekly trend chart with visible size', (
    WidgetTester tester,
  ) async {
    const repository = MockClientRepository();
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: StatsPage(
            statsDataSource: RepositoryStatsDataSource(repository),
            recordsDataSource: RepositoryRecordsDataSource(repository),
          ),
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
