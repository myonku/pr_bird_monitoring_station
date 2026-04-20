import 'package:dio/dio.dart';

import 'package:bms_app/models/api_models.dart';
import 'package:bms_app/models/transport/client_req_dto.dart';
import 'package:bms_app/models/transport/client_resp_dto.dart';
import 'package:bms_app/transport/transport_client.dart';

class ClientApiPaths {
  const ClientApiPaths({
    this.signIn = '/v1/client/auth/sign-in',
    this.refreshSession = '/v1/client/auth/refresh-session',
    this.userProfile = '/v1/client/users/profile',
    this.register = '/v1/client/users/register',
    this.dashboardSummary = '/v1/client/home/summary',
    this.recordStations = '/v1/client/records/stations',
    this.records = '/v1/client/records',
    this.weeklyTrend = '/v1/client/stats/weekly-trend',
    this.rangeSummary = '/v1/client/stats/range-summary',
  });

  final String signIn;
  final String refreshSession;
  final String userProfile;
  final String register;
  final String dashboardSummary;
  final String recordStations;
  final String records;
  final String weeklyTrend;
  final String rangeSummary;
}

class HttpMonitoringClient implements MonitoringClient {
  HttpMonitoringClient({
    Dio? dio,
    String baseUrl = 'http://127.0.0.1:8080',
    this.defaultHeaders = const <String, String>{},
    this.paths = const ClientApiPaths(),
  }) : _dio =
           dio ??
           Dio(
             BaseOptions(
               baseUrl: baseUrl,
               connectTimeout: const Duration(seconds: 10),
               receiveTimeout: const Duration(seconds: 20),
               sendTimeout: const Duration(seconds: 20),
               responseType: ResponseType.json,
               validateStatus: (_) => true,
             ),
           );

  final Dio _dio;
  final Map<String, String> defaultHeaders;
  final ClientApiPaths paths;

  @override
  Future<ClientAuthCredentialsResponse> signIn(
    ClientSignInRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  }) async {
    final response = await _post(
      paths.signIn,
      data: <String, dynamic>{
        'identifier': request.identifier,
        'password': request.password,
      },
      options: options,
    );
    return _parseAuthCredentials(_asMap(response.data));
  }

  @override
  Future<ClientAuthCredentialsResponse> refreshSession(
    ClientRefreshSessionRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  }) async {
    final response = await _post(
      paths.refreshSession,
      data: <String, dynamic>{
        'session_id': request.sessionId,
        'refresh_token': request.refreshToken,
        'token_id': request.tokenId,
        'token_family_id': request.tokenFamilyId,
        'principal_id': request.principalId,
        'scopes': request.scopes,
      },
      options: options,
    );
    return _parseAuthCredentials(_asMap(response.data));
  }

  @override
  Future<ClientUserProfileResponse?> fetchUserProfile(
    ClientUserProfileRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  }) async {
    final response = await _get(
      paths.userProfile,
      query: <String, dynamic>{'identifier': request.identifier},
      options: options,
    );
    final body = response.data;
    if (body == null || body == '') {
      return null;
    }
    return _parseUserProfile(_asMap(body));
  }

  @override
  Future<ClientRegisterResponse> registerUser(
    ClientRegisterRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  }) async {
    final response = await _post(
      paths.register,
      data: <String, dynamic>{
        'username': request.username,
        'email': request.email,
        'phone': request.phone,
        'password': request.password,
      },
      options: options,
    );
    return _parseRegister(_asMap(response.data));
  }

  @override
  Future<ClientDashboardSnapshotResponse> fetchDashboardSnapshot(
    ClientHomeSnapshotRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  }) async {
    final response = await _get(
      paths.dashboardSummary,
      query: <String, dynamic>{'device_id': request.deviceId},
      options: options,
    );
    return _parseDashboard(_asMap(response.data));
  }

  @override
  Future<List<ClientRecordStationOptionResponse>> listRecordStationOptions(
    ClientRecordStationOptionsRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  }) async {
    final response = await _get(
      paths.recordStations,
      query: <String, dynamic>{'include_offline': request.includeOffline},
      options: options,
    );
    final body = response.data;
    if (body is! List) {
      throw ClientHttpException(
        statusCode: response.statusCode ?? -1,
        message: 'record stations response must be a list',
        path: paths.recordStations,
      );
    }

    return body
        .map((item) => _parseRecordStation(_asMap(item)))
        .toList(growable: false);
  }

  @override
  Future<ClientRecordsCursorResponse> listRecordsByCursor(
    ClientRecordsCursorRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  }) async {
    final response = await _get(
      paths.records,
      query: <String, dynamic>{
        'start_at_ms': request.startAtMs,
        'end_at_ms': request.endAtMs,
        'device_id': request.deviceId,
        'keyword': request.keyword,
        'confidence_min': request.confidenceMin,
        'cursor': request.cursor,
        'limit': request.limit,
        'sort': request.sort,
      },
      options: options,
    );
    return _parseRecordsCursor(_asMap(response.data));
  }

  @override
  Future<ClientWeeklyTrendResponse> getWeeklyTrend(
    ClientWeeklyTrendRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  }) async {
    final response = await _get(
      paths.weeklyTrend,
      query: <String, dynamic>{
        'days': request.days,
        'device_id': request.deviceId,
      },
      options: options,
    );
    return _parseWeeklyTrend(_asMap(response.data));
  }

  @override
  Future<ClientRangeSummaryResponse> getRangeSummary(
    ClientRangeSummaryRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  }) async {
    final response = await _get(
      paths.rangeSummary,
      query: <String, dynamic>{
        'start_at_ms': request.startAtMs,
        'end_at_ms': request.endAtMs,
        'device_id': request.deviceId,
      },
      options: options,
    );
    return _parseRangeSummary(_asMap(response.data));
  }

  Future<Response<dynamic>> _get(
    String path, {
    Map<String, dynamic>? query,
    ClientRequestOptions options = const ClientRequestOptions(),
  }) async {
    final response = await _dio.get(
      path,
      queryParameters: _compact(query ?? const <String, dynamic>{}),
      options: _options(options),
    );
    _ensureSuccess(response, path);
    return response;
  }

  Future<Response<dynamic>> _post(
    String path, {
    Map<String, dynamic>? data,
    ClientRequestOptions options = const ClientRequestOptions(),
  }) async {
    final response = await _dio.post(
      path,
      data: _compact(data ?? const <String, dynamic>{}),
      options: _options(options),
    );
    _ensureSuccess(response, path);
    return response;
  }

  Options _options(ClientRequestOptions requestOptions) {
    return Options(
      headers: <String, String>{...defaultHeaders, ...requestOptions.headers},
    );
  }

  Map<String, dynamic> _compact(Map<String, dynamic> raw) {
    final result = <String, dynamic>{};
    raw.forEach((key, value) {
      if (value == null) {
        return;
      }
      if (value is String && value.trim().isEmpty) {
        return;
      }
      result[key] = value;
    });
    return result;
  }

  void _ensureSuccess(Response<dynamic> response, String path) {
    final statusCode = response.statusCode ?? -1;
    if (statusCode >= 200 && statusCode < 300) {
      return;
    }

    throw ClientHttpException(
      statusCode: statusCode,
      message: _extractMessage(response.data) ?? 'request failed',
      path: path,
    );
  }

  String? _extractMessage(dynamic payload) {
    if (payload is Map) {
      final map = _asMap(payload);
      final message = map['message'] ?? map['detail'] ?? map['error'];
      if (message != null) {
        return message.toString();
      }
    }
    return null;
  }

  Map<String, dynamic> _asMap(dynamic value) {
    if (value is Map<String, dynamic>) {
      return value;
    }
    if (value is Map) {
      return value.map((key, val) => MapEntry(key.toString(), val));
    }
    throw const FormatException('invalid json object');
  }

  String _string(dynamic value) => value?.toString() ?? '';

  int _int(dynamic value) {
    if (value is int) {
      return value;
    }
    if (value is num) {
      return value.toInt();
    }
    return int.tryParse(value?.toString() ?? '') ?? 0;
  }

  int? _nullableInt(dynamic value) {
    if (value == null) {
      return null;
    }
    if (value is int) {
      return value;
    }
    if (value is num) {
      return value.toInt();
    }
    return int.tryParse(value.toString());
  }

  double _double(dynamic value) {
    if (value is double) {
      return value;
    }
    if (value is num) {
      return value.toDouble();
    }
    return double.tryParse(value?.toString() ?? '') ?? 0.0;
  }

  double? _nullableDouble(dynamic value) {
    if (value == null) {
      return null;
    }
    if (value is double) {
      return value;
    }
    if (value is num) {
      return value.toDouble();
    }
    return double.tryParse(value.toString());
  }

  bool _bool(dynamic value) {
    if (value is bool) {
      return value;
    }
    final text = value?.toString().toLowerCase() ?? '';
    return text == 'true' || text == '1';
  }

  List<String> _stringList(dynamic value) {
    if (value is! List) {
      return const <String>[];
    }
    return value.map((item) => item.toString()).toList(growable: false);
  }

  Map<String, String> _stringMap(dynamic value) {
    if (value is! Map) {
      return const <String, String>{};
    }
    final result = <String, String>{};
    value.forEach((key, val) {
      result[key.toString()] = val.toString();
    });
    return result;
  }

  ClientAuthCredentialsResponse _parseAuthCredentials(
    Map<String, dynamic> json,
  ) {
    return ClientAuthCredentialsResponse(
      accessToken: _string(json['access_token']),
      refreshToken: _string(json['refresh_token']),
      downstreamToken: _string(json['downstream_token']),
      tokenType: _string(json['token_type']),
      sessionId: _string(json['session_id']),
      tokenId: _string(json['token_id']),
      principalId: _string(json['principal_id']),
      tokenFamilyId: _string(json['token_family_id']),
      scopes: _stringList(json['scopes']),
      issuedAtMs: _int(json['issued_at_ms']),
      accessExpiresAtMs: _int(json['access_expires_at_ms']),
      refreshExpiresAtMs: _int(json['refresh_expires_at_ms']),
      persisted: _bool(json['persisted']),
    );
  }

  ClientUserProfileResponse _parseUserProfile(Map<String, dynamic> json) {
    return ClientUserProfileResponse(
      userId: _string(json['user_id']),
      username: _string(json['username']),
      displayName: _string(json['display_name']),
      name: _string(json['name']),
      role: _string(json['role']),
      email: _string(json['email']),
      phone: _string(json['phone']),
      avatarB64: _string(json['avatar_b64']),
    );
  }

  ClientRegisterResponse _parseRegister(Map<String, dynamic> json) {
    return ClientRegisterResponse(
      ok: _bool(json['ok']),
      errorCode: _string(json['error_code']),
      message: _string(json['message']),
    );
  }

  ClientDashboardSnapshotResponse _parseDashboard(Map<String, dynamic> json) {
    final topUploadStation = _parseUploadStation(
      _asMap(json['top_upload_station'] ?? const <String, dynamic>{}),
    );
    final latestUpload = _parseLatestUpload(
      _asMap(json['latest_upload'] ?? const <String, dynamic>{}),
    );

    final recentRaw = json['recent_records'];
    final recentRecords = recentRaw is List
        ? recentRaw
              .map((item) => _parseBirdRecord(_asMap(item)))
              .toList(growable: false)
        : const <ClientBirdRecordResponse>[];

    return ClientDashboardSnapshotResponse(
      todayRecognitionCount: _int(json['today_recognition_count']),
      todayUploadCount: _int(json['today_upload_count']),
      onlineStationCount: _int(json['online_station_count']),
      activeStationCount: _int(json['active_station_count']),
      topUploadStation: topUploadStation,
      latestUpload: latestUpload,
      recentRecords: recentRecords,
    );
  }

  ClientUploadStationSummaryResponse _parseUploadStation(
    Map<String, dynamic> json,
  ) {
    return ClientUploadStationSummaryResponse(
      deviceId: _string(json['device_id']),
      deviceName: _string(json['device_name']),
      uploadCount: _int(json['upload_count']),
    );
  }

  ClientLatestUploadSummaryResponse _parseLatestUpload(
    Map<String, dynamic> json,
  ) {
    return ClientLatestUploadSummaryResponse(
      deviceId: _string(json['device_id']),
      deviceName: _string(json['device_name']),
      uploadedAtMs: _nullableInt(json['uploaded_at_ms']),
      uploadedAtLabel: _string(json['uploaded_at_label']),
    );
  }

  ClientRecordStationOptionResponse _parseRecordStation(
    Map<String, dynamic> json,
  ) {
    return ClientRecordStationOptionResponse(
      deviceId: _string(json['device_id']),
      deviceName: _string(json['device_name']),
      online: _bool(json['online']),
      status: _string(json['status']),
    );
  }

  ClientBirdRecordResponse _parseBirdRecord(Map<String, dynamic> json) {
    return ClientBirdRecordResponse(
      id: _string(json['id']),
      species: _string(json['species']),
      scientificName: _string(json['scientific_name']),
      capturedAtMs: _int(json['captured_at_ms']),
      capturedAtLabel: _string(json['captured_at_label']),
      deviceId: _string(json['device_id']),
      deviceName: _string(json['device_name']),
      confidence: _double(json['confidence']),
      temperatureC: _nullableDouble(json['temperature_c']),
      humidityPct: _nullableInt(json['humidity_pct']),
      uploadSummary: _string(json['upload_summary']),
      speciesIntro: _string(json['species_intro']),
      imageB64: _string(json['image_b64']),
      mediaRefs: _stringList(json['media_refs']),
      processingSource: _string(json['processing_source']),
      modelVersion: _string(json['model_version']),
      recordStatus: _string(json['record_status']),
      summaryText: _string(json['summary_text']),
      speciesEntityId: _string(json['species_entity_id']),
      metadata: _stringMap(json['metadata']),
    );
  }

  ClientRecordsCursorResponse _parseRecordsCursor(Map<String, dynamic> json) {
    final itemsRaw = json['items'];
    final items = itemsRaw is List
        ? itemsRaw
              .map((item) => _parseBirdRecord(_asMap(item)))
              .toList(growable: false)
        : const <ClientBirdRecordResponse>[];

    return ClientRecordsCursorResponse(
      items: items,
      nextCursor: _string(json['next_cursor']),
      hasMore: _bool(json['has_more']),
    );
  }

  ClientWeeklyTrendResponse _parseWeeklyTrend(Map<String, dynamic> json) {
    final seriesRaw = json['series'];
    final series = seriesRaw is List
        ? seriesRaw
              .map((item) => _parseTrendPoint(_asMap(item)))
              .toList(growable: false)
        : const <ClientTrendPointResponse>[];

    return ClientWeeklyTrendResponse(
      series: series,
      total: _int(json['total']),
    );
  }

  ClientRangeSummaryResponse _parseRangeSummary(Map<String, dynamic> json) {
    final dailyRaw = json['daily_distribution'];
    final speciesRaw = json['species_shares'];

    final dailyDistribution = dailyRaw is List
        ? dailyRaw
              .map((item) => _parseTrendPoint(_asMap(item)))
              .toList(growable: false)
        : const <ClientTrendPointResponse>[];
    final speciesShares = speciesRaw is List
        ? speciesRaw
              .map((item) => _parseSpeciesShare(_asMap(item)))
              .toList(growable: false)
        : const <ClientSpeciesShareResponse>[];

    return ClientRangeSummaryResponse(
      totalCount: _int(json['total_count']),
      dailyDistribution: dailyDistribution,
      speciesShares: speciesShares,
      peakDay: _parsePeakDay(
        _asMap(json['peak_day'] ?? const <String, dynamic>{}),
      ),
      peakDevice: _parsePeakDevice(
        _asMap(json['peak_device'] ?? const <String, dynamic>{}),
      ),
    );
  }

  ClientTrendPointResponse _parseTrendPoint(Map<String, dynamic> json) {
    return ClientTrendPointResponse(
      label: _string(json['label']),
      value: _int(json['value']),
      dateMs: _nullableInt(json['date_ms']),
    );
  }

  ClientSpeciesShareResponse _parseSpeciesShare(Map<String, dynamic> json) {
    return ClientSpeciesShareResponse(
      label: _string(json['label']),
      value: _int(json['value']),
      ratio: _double(json['ratio']),
      speciesEntityId: _string(json['species_entity_id']),
      colorHex: _string(json['color_hex']),
    );
  }

  ClientPeakDayResponse _parsePeakDay(Map<String, dynamic> json) {
    return ClientPeakDayResponse(
      label: _string(json['label']),
      value: _int(json['value']),
      dateMs: _nullableInt(json['date_ms']),
    );
  }

  ClientPeakDeviceSummaryResponse _parsePeakDevice(Map<String, dynamic> json) {
    return ClientPeakDeviceSummaryResponse(
      deviceId: _string(json['device_id']),
      deviceName: _string(json['device_name']),
      recordCount: _int(json['record_count']),
    );
  }
}
