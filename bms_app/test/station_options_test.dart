import 'package:flutter_test/flutter_test.dart';

import 'package:bms_app/controller/controller.dart';
import 'package:bms_app/credential_manager/credential_manager.dart';
import 'package:bms_app/models/api_models.dart';
import 'package:bms_app/models/common.dart';
import 'package:bms_app/models/transport/client_req_dto.dart';
import 'package:bms_app/models/transport/client_resp_dto.dart';
import 'package:bms_app/transport/transport_client.dart';

class _RecordingMonitoringClient implements MonitoringClient {
  ClientRecordStationOptionsRequest? lastStationOptionsRequest;

  @override
  Future<List<ClientRecordStationOptionResponse>> listRecordStationOptions(
    ClientRecordStationOptionsRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  }) async {
    lastStationOptionsRequest = request;
    return const [
      ClientRecordStationOptionResponse(
        deviceId: 'station-1',
        deviceName: '一号站点',
        online: true,
        status: 'online',
      ),
      ClientRecordStationOptionResponse(
        deviceId: 'station-2',
        deviceName: '二号站点',
        online: false,
        status: 'offline',
      ),
    ];
  }

  @override
  Future<ClientAuthCredentialsResponse> signIn(
    ClientSignInRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  }) =>
      throw UnimplementedError();

  @override
  Future<ClientAuthCredentialsResponse> refreshSession(
    ClientRefreshSessionRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  }) =>
      throw UnimplementedError();

  @override
  Future<ClientUserProfileResponse?> fetchUserProfile(
    ClientUserProfileRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  }) =>
      throw UnimplementedError();

  @override
  Future<ClientRegisterResponse> registerUser(
    ClientRegisterRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  }) =>
      throw UnimplementedError();

  @override
  Future<ClientDashboardSnapshotResponse> fetchDashboardSnapshot(
    ClientHomeSnapshotRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  }) =>
      throw UnimplementedError();

  @override
  Future<ClientRecordsCursorResponse> listRecordsByCursor(
    ClientRecordsCursorRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  }) =>
      throw UnimplementedError();

  @override
  Future<ClientWeeklyTrendResponse> getWeeklyTrend(
    ClientWeeklyTrendRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  }) =>
      throw UnimplementedError();

  @override
  Future<ClientRangeSummaryResponse> getRangeSummary(
    ClientRangeSummaryRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  }) =>
      throw UnimplementedError();
}

void main() {
  test('fetchStationOptions requests offline stations too', () async {
    final client = _RecordingMonitoringClient();
    final controller = MonitoringController(
      client: client,
      credentials: MonitoringCredentialManager(initialMode: AppMode.noAuth),
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

    final stations = await controller.fetchStationOptions();

    expect(client.lastStationOptionsRequest, isNotNull);
    expect(client.lastStationOptionsRequest!.includeOffline, isTrue);
    expect(stations, hasLength(2));
    expect(stations.first.deviceId, 'station-1');
    expect(stations.last.deviceId, 'station-2');
  });
}
