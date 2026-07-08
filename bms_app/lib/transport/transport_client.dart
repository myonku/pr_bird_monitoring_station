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

  /// 发送聊天消息。
  Future<ChatSendResponse> chatSend(
    ChatSendRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  });

  /// 获取用户会话列表。
  Future<ChatSessionListResponse> chatSessionList(
    ChatSessionListRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  });

  /// 获取单个会话详情。
  Future<ChatSessionDetailResponse> chatSessionDetail(
    ChatSessionGetRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  });

  /// 删除会话。
  Future<ChatSessionDeleteResponse> chatSessionDelete(
    ChatSessionDeleteRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  });

  /// 创建新会话。
  Future<ChatSessionCreateResponse> chatSessionCreate(
    ChatSessionCreateRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  });
}
