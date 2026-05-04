import 'package:bms_app/models/transport/client_resp_dto.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:bms_app/controller/controller.dart';
import 'package:bms_app/credential_manager/credential_manager.dart';
import 'package:bms_app/models/api_models.dart';
import 'package:bms_app/models/common.dart';
import 'package:bms_app/models/transport/client_req_dto.dart';
import 'package:bms_app/transport/http_client.dart';

const String _gatewayBaseUrl = 'http://127.0.0.1:8080';
const String _loginIdentifier = 'example_user';
const String _loginPassword = '123456';

void main() {
  test(
    'authenticated business read interfaces are accepted by authcontrol',
    () async {
      final client = HttpMonitoringClient(baseUrl: _gatewayBaseUrl);
      final controller = MonitoringController(
        client: client,
        credentials: MonitoringCredentialManager(
          initialMode: AppMode.development,
        ),
        defaultUser: const AppUser(
          name: '测试用户',
          role: '系统演示账号',
          phone: '138-0000-0000',
          userId: '7a4a7c0c-6b12-4d5f-9a8f-7b2a12d02f19',
          username: 'demo_user',
          displayName: '测试用户',
          email: 'demo_user@example.com',
        ),
      );

      await controller.signIn(
        identifier: _loginIdentifier,
        password: _loginPassword,
      );
      final authHeaders = await controller.buildAuthHeaders();

      final profile = await client.fetchUserProfile(
        const ClientUserProfileRequest(identifier: 'missing_user'),
        options: ClientRequestOptions(headers: authHeaders),
      );
      expect(profile, isNotNull);
      expect(profile!.userId, isEmpty);
      expect(profile.username, isEmpty);
      expect(profile.displayName, isEmpty);
      expect(profile.name, isEmpty);
      expect(profile.role, isEmpty);
      expect(profile.email, isEmpty);
      expect(profile.phone, isEmpty);
      expect(profile.avatarB64, isEmpty);

      final snapshot = await client.fetchDashboardSnapshot(
        const ClientHomeSnapshotRequest(deviceId: 'test-device'),
        options: ClientRequestOptions(headers: authHeaders),
      );
      expect(snapshot.todayRecognitionCount, 0);
      expect(snapshot.todayUploadCount, 0);
      // onlineStationCount 依赖实体数据，至少 1
      expect(snapshot.onlineStationCount, greaterThanOrEqualTo(1));
      // 无业务记录时 activeStationCount 应为 0
      expect(snapshot.activeStationCount, 0);
      // 无业务上传时 topUploadStation 返回空设备 ID
      expect(snapshot.topUploadStation.deviceId, isEmpty);
      expect(snapshot.topUploadStation.uploadCount, 0);
      // 无业务上传时 latestUpload 返回空
      expect(snapshot.latestUpload.deviceId, isEmpty);
      expect(snapshot.latestUpload.uploadedAtMs, isNull);
      expect(snapshot.recentRecords, isEmpty);

      // 无业务上传时不检查 topUploadStation.deviceName / latestUpload.deviceName / latestUpload.uploadedAtLabel 的精确值

      final stationOptions = await client.listRecordStationOptions(
        const ClientRecordStationOptionsRequest(includeOffline: true),
        options: ClientRequestOptions(headers: authHeaders),
      );
      // 系统中存在设备实体，应至少返回一个站点选项
      expect(stationOptions, isNotEmpty);

      final now = DateTime.now();
      final startAt = now.subtract(const Duration(days: 7));
      final cursorPage = await client.listRecordsByCursor(
        ClientRecordsCursorRequest(
          startAtMs: startAt.millisecondsSinceEpoch,
          endAtMs: now.millisecondsSinceEpoch,
          limit: 20,
        ),
        options: ClientRequestOptions(headers: authHeaders),
      );
      expect(cursorPage.items, isEmpty);
      expect(cursorPage.nextCursor, isEmpty);
      expect(cursorPage.hasMore, isFalse);

      final weeklyTrend = await client.getWeeklyTrend(
        const ClientWeeklyTrendRequest(days: 7),
        options: ClientRequestOptions(headers: authHeaders),
      );
      expect(weeklyTrend.total, 0);
      // 系列长度取决于日期计算，至少 7 天
      expect(weeklyTrend.series.length, greaterThanOrEqualTo(7));
      for (final ClientTrendPointResponse point in weeklyTrend.series) {
        expect(point.value, 0);
      }

      final rangeSummary = await client.getRangeSummary(
        ClientRangeSummaryRequest(
          startAtMs: startAt.millisecondsSinceEpoch,
          endAtMs: now.millisecondsSinceEpoch,
        ),
        options: ClientRequestOptions(headers: authHeaders),
      );
      expect(rangeSummary.totalCount, 0);
      // 日分布长度取决于日期范围计算，至少 7 天
      expect(rangeSummary.dailyDistribution.length, greaterThanOrEqualTo(7));
      for (final ClientTrendPointResponse point
          in rangeSummary.dailyDistribution) {
        expect(point.value, 0);
      }
      expect(rangeSummary.speciesShares, isEmpty);
      // 无业务数据时 peakDay.value 应为 0（label 可能是 '-' 或某个日期，取决于日期范围计算）
      expect(rangeSummary.peakDay.value, 0);
      expect(rangeSummary.peakDevice.deviceId, isEmpty);
      expect(rangeSummary.peakDevice.deviceName, '-');
      expect(rangeSummary.peakDevice.recordCount, 0);
    },
  );

  test('business request without auth headers is rejected', () async {
    final client = HttpMonitoringClient(baseUrl: _gatewayBaseUrl);

    await expectLater(
      () => client.fetchUserProfile(
        const ClientUserProfileRequest(identifier: 'missing_user'),
      ),
      throwsA(
        isA<ClientHttpException>().having(
          (error) => error.statusCode,
          'statusCode',
          401,
        ),
      ),
    );
  });
}
