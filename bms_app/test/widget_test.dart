import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:bms_app/app/bms_app.dart';
import 'package:bms_app/controller/controller.dart';
import 'package:bms_app/credential_manager/credential_manager.dart';
import 'package:bms_app/models/auth_models.dart';
import 'package:bms_app/models/common.dart';
import 'package:bms_app/pages/records/records_page.dart';
import 'package:bms_app/pages/stats/stats_page.dart';
import 'package:bms_app/storage/auth_stores.dart';
import 'package:bms_app/transport/mock_client.dart';

MonitoringController _buildNoAuthController() {
  return MonitoringController(
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

class _RecordsPageTestController extends MonitoringController {
  _RecordsPageTestController()
    : super(
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

  @override
  Future<List<RecordStationOption>> fetchStationOptions() async {
    return const [
      RecordStationOption(deviceId: 'station-1', deviceName: '测试站点'),
    ];
  }

  @override
  Future<RecordCursorPage> fetchRecordsByCursor({
    DateTimeRange? dateRange,
    String? stationId,
    String? cursor,
    int limit = 20,
  }) async {
    if (dateRange == null) {
      return const RecordCursorPage(
        items: [],
        nextCursor: null,
        hasMore: false,
      );
    }

    return RecordCursorPage(
      items: [
        BirdRecord(
          id: 'record-1',
          species: '白鹭',
          scientificName: 'Egretta garzetta',
          capturedAtTime: DateTime(2026, 4, 11, 9, 20),
          stationName: '测试站点',
          capturedAt: '2026-04-11 09:20',
          confidence: 0.97,
          temperature: 18.4,
          humidity: 64,
          uploadSummary: '测试记录',
          speciesIntro: '测试记录',
          accent: Color(0xFF0B7A75),
        ),
      ],
      nextCursor: null,
      hasMore: false,
    );
  }
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
    final controller = _buildNoAuthController();
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(body: StatsPage(monitoringController: controller)),
      ),
    );
    await tester.pumpAndSettle();

    final customPaints = find.byType(CustomPaint);
    expect(customPaints, findsWidgets);

    final weeklyTrendSize = tester.getSize(customPaints.first);
    expect(weeklyTrendSize.width, greaterThan(0));
    expect(weeklyTrendSize.height, greaterThan(0));
  });

  testWidgets('loads records on first entry', (WidgetTester tester) async {
    final controller = _RecordsPageTestController();
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(body: RecordsPage(monitoringController: controller)),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.text('白鹭'), findsOneWidget);
    expect(find.text('没有找到匹配记录'), findsNothing);
  });

  test('persists auth session to disk and reloads it', () async {
    final tempDirectory = Directory.systemTemp.createTempSync(
      'bms_auth_store_test_',
    );
    addTearDown(() {
      if (tempDirectory.existsSync()) {
        tempDirectory.deleteSync(recursive: true);
      }
    });

    final filePath =
        '${tempDirectory.path}${Platform.pathSeparator}session.json';
    final session = AuthSession(
      loginIdentifier: 'tester',
      credentials: const AuthCredentials(
        accessToken: 'access-token',
        refreshToken: 'refresh-token',
        downstreamToken: 'downstream-token',
        sessionId: 'session-id',
        tokenId: 'token-id',
        principalId: 'principal-id',
        tokenFamilyId: 'family-id',
        scopes: ['client:read'],
        persisted: true,
      ),
      mode: AppMode.development,
      signedInAt: DateTime(2026, 4, 19, 12, 30),
    );

    final store = PersistentAuthSessionStore(storageFilePath: filePath);
    await store.write(session);

    final reloadedStore = PersistentAuthSessionStore(storageFilePath: filePath);
    final reloadedSession = reloadedStore.read();

    expect(reloadedSession, isNotNull);
    expect(reloadedSession!.loginIdentifier, session.loginIdentifier);
    expect(reloadedSession.mode, session.mode);
    expect(
      reloadedSession.credentials.accessToken,
      session.credentials.accessToken,
    );
    expect(
      reloadedSession.credentials.refreshToken,
      session.credentials.refreshToken,
    );
    expect(reloadedSession.credentials.persisted, isTrue);

    await reloadedStore.clear();
    final clearedStore = PersistentAuthSessionStore(storageFilePath: filePath);
    expect(clearedStore.read(), isNull);
  });
}
