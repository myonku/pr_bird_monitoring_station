import 'package:flutter/material.dart';

import 'package:bms_app/models/auth_models.dart';
import 'package:bms_app/credential_manager/credential_manager.dart';
import 'package:bms_app/data_source/monitoring_repository.dart';
import 'package:bms_app/models/api_models.dart';
import 'package:bms_app/models/common.dart';
import 'package:bms_app/transport/transport_client.dart';
import 'package:bms_app/models/transport/client_resp_dto.dart';
import 'package:bms_app/models/transport/client_req_dto.dart';



class ClientBackedMonitoringRepository implements MonitoringRepository {
  ClientBackedMonitoringRepository({
    required MonitoringClient client,
    required MonitoringCredentialManager credentials,
    required AppUser defaultUser,
  })  : _client = client,
        _credentials = credentials,
        _defaultUser = defaultUser;

  final MonitoringClient _client;
  final MonitoringCredentialManager _credentials;
  final AppUser _defaultUser;

  DashboardSnapshot? _lastDashboardSnapshot;
  List<BirdRecord> _lastRecords = const [];
  List<TrendPoint> _lastWeeklyTrend = const [];
  final List<SpeciesShare> _lastSpeciesShares = const [];

  @override
  int countTodayMonitoringRecords() =>
      _lastDashboardSnapshot?.todayRecognitionCount ?? 0;

  @override
  int countTodayUploadRecords() => _lastDashboardSnapshot?.todayUploadCount ?? 0;

  @override
  int countOnlineStations() => _lastDashboardSnapshot?.onlineStationCount ?? 0;

  @override
  UploadStationSummary getTodayTopUploadStation() =>
      _lastDashboardSnapshot?.topUploadStation ??
      const UploadStationSummary(deviceId: '', deviceName: '', uploadCount: 0);

  @override
  LatestUploadSummary getLatestUploadSummary() =>
      _lastDashboardSnapshot?.latestUpload ??
      const LatestUploadSummary(
        deviceId: '',
        deviceName: '',
        uploadedAtLabel: '',
      );

  @override
  Future<DashboardSnapshot> fetchDashboardSnapshot() async {
    final response = await _client.fetchDashboardSnapshot(
      const ClientHomeSnapshotRequest(),
      options: ClientRequestOptions(headers: await _authHeaders()),
    );

    final snapshot = _toDashboardSnapshot(response);
    _lastDashboardSnapshot = snapshot;
    _lastRecords = snapshot.recentRecords;
    return snapshot;
  }

  @override
  AppUser get defaultUser => _defaultUser;

  @override
  Future<AppUser?> fetchUserProfile(String identifier) async {
    final normalized = identifier.trim();
    if (normalized.isEmpty) {
      return _defaultUser;
    }

    if (_credentials.mode == AppMode.noAuth) {
      try {
        final response = await _client.fetchUserProfile(
          ClientUserProfileRequest(identifier: normalized),
          options: const ClientRequestOptions(headers: <String, String>{}),
        );
        return response == null ? _defaultUser : _toAppUser(response);
      } catch (_) {
        return _defaultUser;
      }
    }

    final response = await _client.fetchUserProfile(
      ClientUserProfileRequest(identifier: normalized),
      options: ClientRequestOptions(headers: await _authHeaders()),
    );
    return response == null ? _defaultUser : _toAppUser(response);
  }

  @override
  Future<RegistrationResult> registerUser({
    required String username,
    String email = '',
    String phone = '',
    required String password,
  }) async {
    final response = await _client.registerUser(
      ClientRegisterRequest(
        username: username,
        email: email,
        phone: phone,
        password: password,
      ),
    );

    return _toRegistrationResult(response);
  }

  @override
  List<BirdRecord> get records => _lastRecords;

  @override
  Future<List<RecordStationOption>> fetchStationOptions() async {
    final response = await _client.listRecordStationOptions(
      const ClientRecordStationOptionsRequest(),
      options: ClientRequestOptions(headers: await _authHeaders()),
    );

    return response.map(_toStationOption).toList(growable: false);
  }

  @override
  Future<RecordCursorPage> fetchRecordsByCursor({
    DateTimeRange? dateRange,
    String? stationId,
    String? cursor,
    int limit = 20,
  }) async {
    final response = await _client.listRecordsByCursor(
      ClientRecordsCursorRequest(
        startAtMs: dateRange == null ? null : dateRange.start.millisecondsSinceEpoch,
        endAtMs: dateRange == null ? null : dateRange.end.millisecondsSinceEpoch,
        deviceId: stationId,
        cursor: cursor,
        limit: limit,
      ),
      options: ClientRequestOptions(headers: await _authHeaders()),
    );

    final page = RecordCursorPage(
      items: response.items.map(_toBirdRecord).toList(growable: false),
      nextCursor: response.nextCursor.isEmpty ? null : response.nextCursor,
      hasMore: response.hasMore,
    );
    _lastRecords = page.items;
    return page;
  }

  @override
  Future<List<TrendPoint>> fetchWeeklyTrend({
    int days = 7,
    String? stationId,
  }) async {
    final response = await _client.getWeeklyTrend(
      ClientWeeklyTrendRequest(days: days, deviceId: stationId),
      options: ClientRequestOptions(headers: await _authHeaders()),
    );

    final points = response.series
        .map((point) => TrendPoint(label: point.label, value: point.value, dateMs: point.dateMs))
        .toList(growable: false);
    _lastWeeklyTrend = points;
    return points;
  }

  @override
  Future<List<BirdRecord>> fetchRecords({
    DateTimeRange? dateRange,
    String? stationId,
  }) async {
    final allRecords = <BirdRecord>[];
    String? nextCursor;

    while (true) {
      final page = await fetchRecordsByCursor(
        dateRange: dateRange,
        stationId: stationId,
        cursor: nextCursor,
        limit: 50,
      );
      allRecords.addAll(page.items);
      if (!page.hasMore || page.nextCursor == null || page.nextCursor!.isEmpty) {
        break;
      }
      nextCursor = page.nextCursor;
    }

    _lastRecords = allRecords;
    return allRecords;
  }

  @override
  List<TrendPoint> get trends => _lastWeeklyTrend;

  @override
  List<SpeciesShare> get speciesShares => _lastSpeciesShares;

  Future<Map<String, String>> _authHeaders() {
    return _credentials.buildAuthHeaders(refreshSession: _refreshSession);
  }

  Future<AuthSession> _refreshSession(AuthSession session) async {
    final response = await _client.refreshSession(
      ClientRefreshSessionRequest(
        sessionId: session.credentials.sessionId?.trim() ?? '',
        refreshToken: session.credentials.refreshToken?.trim() ?? '',
        tokenId: session.credentials.tokenId?.trim() ?? '',
        tokenFamilyId: session.credentials.tokenFamilyId?.trim() ?? '',
        principalId: session.credentials.principalId?.trim() ?? '',
        scopes: session.credentials.scopes,
      ),
    );

    final refreshed = AuthSession(
      loginIdentifier: session.loginIdentifier,
      credentials: _toAuthCredentials(response),
      mode: session.mode,
      signedInAt: session.signedInAt,
    );
    await _credentials.storeSession(refreshed);
    return refreshed;
  }

  AppUser _toAppUser(ClientUserProfileResponse response) {
    return AppUser(
      userId: response.userId,
      username: response.username,
      displayName: response.displayName,
      name: response.name,
      role: response.role,
      email: response.email,
      phone: response.phone,
      avatarSeed: response.avatarSeed,
    );
  }

  RegistrationResult _toRegistrationResult(ClientRegisterResponse response) {
    return RegistrationResult(
      ok: response.ok,
      errorCode: response.errorCode,
      message: response.message,
    );
  }

  DashboardSnapshot _toDashboardSnapshot(ClientDashboardSnapshotResponse response) {
    return DashboardSnapshot(
      todayRecognitionCount: response.todayRecognitionCount,
      todayUploadCount: response.todayUploadCount,
      onlineStationCount: response.onlineStationCount,
      activeStationCount: response.activeStationCount,
      topUploadStation: _toUploadStationSummary(response.topUploadStation),
      latestUpload: _toLatestUploadSummary(response.latestUpload),
      recentRecords: response.recentRecords.map(_toBirdRecord).toList(growable: false),
    );
  }

  UploadStationSummary _toUploadStationSummary(
    ClientUploadStationSummaryResponse response,
  ) {
    return UploadStationSummary(
      deviceId: response.deviceId,
      deviceName: response.deviceName,
      uploadCount: response.uploadCount,
    );
  }

  LatestUploadSummary _toLatestUploadSummary(
    ClientLatestUploadSummaryResponse response,
  ) {
    return LatestUploadSummary(
      deviceId: response.deviceId,
      deviceName: response.deviceName,
      uploadedAtLabel: response.uploadedAtLabel,
      uploadedAtMs: response.uploadedAtMs,
    );
  }

  RecordStationOption _toStationOption(ClientRecordStationOptionResponse response) {
    return RecordStationOption(
      deviceId: response.deviceId,
      deviceName: response.deviceName,
    );
  }

  BirdRecord _toBirdRecord(ClientBirdRecordResponse response) {
    return BirdRecord(
      id: response.id,
      recordId: response.id,
      species: response.species,
      scientificName: response.scientificName,
      capturedAtTime: DateTime.fromMillisecondsSinceEpoch(response.capturedAtMs),
      stationName: response.deviceName.isNotEmpty ? response.deviceName : response.deviceId,
      capturedAt: response.capturedAtLabel,
      confidence: response.confidence,
      temperature: response.temperatureC ?? 0.0,
      humidity: response.humidityPct ?? 0,
      uploadSummary: response.uploadSummary,
      speciesIntro: response.speciesIntro,
      accent: _accentFor(response),
      deviceId: response.deviceId,
      deviceName: response.deviceName,
      speciesEntityId: response.speciesEntityId.isEmpty ? null : response.speciesEntityId,
      capturedAtMs: response.capturedAtMs,
      temperatureC: response.temperatureC,
      humidityPct: response.humidityPct,
      mediaRefs: response.mediaRefs,
      processingSource: response.processingSource,
      modelVersion: response.modelVersion,
      recordStatus: response.recordStatus,
      summaryText: response.summaryText,
    );
  }

  AuthCredentials _toAuthCredentials(ClientAuthCredentialsResponse response) {
    return AuthCredentials(
      accessToken: response.accessToken,
      refreshToken: response.refreshToken,
      downstreamToken: response.downstreamToken,
      tokenType: response.tokenType,
      sessionId: response.sessionId,
      tokenId: response.tokenId,
      principalId: response.principalId,
      tokenFamilyId: response.tokenFamilyId,
      scopes: response.scopes,
      issuedAtMs: response.issuedAtMs,
      accessExpiresAtMs: response.accessExpiresAtMs,
      refreshExpiresAtMs: response.refreshExpiresAtMs,
      persisted: response.persisted,
    );
  }

  Color _accentFor(ClientBirdRecordResponse response) {
    final palette = <Color>[
      const Color(0xFF0B7A75),
      const Color(0xFF125D98),
      const Color(0xFFC97C1D),
      const Color(0xFF6D597A),
      const Color(0xFF2A9D8F),
      const Color(0xFFE76F51),
    ];
    final hash = response.species.hashCode.abs();
    return palette[hash % palette.length];
  }
}
