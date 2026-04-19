import 'package:bms_app/models/api_models.dart';
import 'package:bms_app/models/transport/client_resp_dto.dart';
import 'package:bms_app/models/transport/client_req_dto.dart';

abstract class MonitoringClient {
  Future<ClientAuthCredentialsResponse> signIn(
    ClientSignInRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  });

  Future<ClientAuthCredentialsResponse> refreshSession(
    ClientRefreshSessionRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  });

  Future<ClientUserProfileResponse?> fetchUserProfile(
    ClientUserProfileRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  });

  Future<ClientRegisterResponse> registerUser(
    ClientRegisterRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  });

  Future<ClientDashboardSnapshotResponse> fetchDashboardSnapshot(
    ClientHomeSnapshotRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  });

  Future<List<ClientRecordStationOptionResponse>> listRecordStationOptions(
    ClientRecordStationOptionsRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  });

  Future<ClientRecordsCursorResponse> listRecordsByCursor(
    ClientRecordsCursorRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  });

  Future<ClientWeeklyTrendResponse> getWeeklyTrend(
    ClientWeeklyTrendRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  });

  Future<ClientRangeSummaryResponse> getRangeSummary(
    ClientRangeSummaryRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  });
}
