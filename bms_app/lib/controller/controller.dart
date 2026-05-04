import 'package:flutter/material.dart';

import 'package:bms_app/credential_manager/credential_manager.dart';
import 'package:bms_app/models/api_models.dart';
import 'package:bms_app/models/auth_models.dart';
import 'package:bms_app/models/common.dart';
import 'package:bms_app/models/transport/client_req_dto.dart';
import 'package:bms_app/models/transport/client_resp_dto.dart';
import 'package:bms_app/transport/transport_client.dart';

class MonitoringController extends ChangeNotifier {
  MonitoringController({
    required MonitoringClient client,
    required MonitoringCredentialManager credentials,
    required AppUser defaultUser,
  }) : _client = client,
       _credentials = credentials,
       _defaultUser = defaultUser,
       _activeUser = defaultUser,
       _loginIdentifier = credentials.session?.loginIdentifier;

  final MonitoringClient _client;
  final MonitoringCredentialManager _credentials;
  final AppUser _defaultUser;

  AppUser _activeUser;
  String? _loginIdentifier;
  DashboardSnapshot? _lastDashboardSnapshot;
  List<RecordStationOption> _lastStationOptions = const [];
  List<BirdRecord> _lastRecords = const [];
  List<TrendPoint> _lastWeeklyTrend = const [];
  List<SpeciesShare> _lastSpeciesShares = const [];

  AppMode get mode => _credentials.mode;
  bool get isAuthenticated => _credentials.hasSession;
  AppUser get activeUser => _activeUser;
  AppUser get defaultUser => _defaultUser;
  String? get loginIdentifier => _loginIdentifier;
  DashboardSnapshot? get lastDashboardSnapshot => _lastDashboardSnapshot;
  List<RecordStationOption> get stationOptions => _lastStationOptions;
  List<BirdRecord> get records => _lastRecords;
  List<TrendPoint> get trends => _lastWeeklyTrend;
  List<SpeciesShare> get speciesShares => _lastSpeciesShares;
  AuthCredentials? get credentials => _credentials.credentials;
  DateTime? get signedInAt => _credentials.signedInAt;

  String get statusLabel => isAuthenticated ? '已登录' : '未登录';

  String get credentialPolicyLabel => switch (mode) {
    AppMode.development => '测试模式：凭证启用',
    AppMode.noAuth => '无认证模式：空凭证',
  };

  String get credentialStorageLabel => switch (mode) {
    AppMode.development =>
      _credentials.credentials?.persisted == true ? '已缓存凭证' : '未缓存凭证',
    AppMode.noAuth => '已禁用',
  };

  bool get credentialsEnabled => _credentials.credentialsEnabled;

  String? get accessToken => _credentials.accessToken;

  String? get refreshToken => _credentials.refreshToken;

  Future<Map<String, String>> buildAuthHeaders() {
    return _credentials.buildAuthHeaders(refreshSession: _refreshSession);
  }

  Future<void> switchMode(AppMode nextMode) async {
    if (mode == nextMode) {
      return;
    }

    await _credentials.setMode(nextMode);
    _clearCachedState();
    notifyListeners();
  }

  Future<void> signIn({
    required String identifier,
    required String password,
  }) async {
    final normalizedIdentifier = identifier.trim();
    _loginIdentifier = normalizedIdentifier;
    _clearPageData();

    final now = DateTime.now();
    await _credentials.setMode(mode);

    if (mode == AppMode.noAuth) {
      await _credentials.storeSession(
        AuthSession(
          loginIdentifier: normalizedIdentifier,
          credentials: const AuthCredentials(),
          mode: mode,
          signedInAt: now,
        ),
      );
      _activeUser = _defaultUser;
      notifyListeners();
      return;
    }

    final credentials = await _client.signIn(
      ClientSignInRequest(identifier: identifier, password: password),
    );

    final session = _toAuthSession(
      loginIdentifier: normalizedIdentifier,
      mode: mode,
      credentials: credentials,
      signedInAt: now,
    );
    if (!session.credentials.hasAccessToken ||
        !session.credentials.hasRefreshToken ||
        !session.credentials.toAuthHeaders().isReadyForHttp) {
      throw StateError('登录信息已失效，请重新登录');
    }

    await _credentials.storeSession(session);
    _activeUser = _defaultUser;
    notifyListeners();
  }

  Future<AppUser?> loadCurrentUserProfile() {
    return fetchUserProfile(_loginIdentifier ?? '');
  }

  Future<AppUser?> fetchUserProfile(String identifier) async {
    final normalized = identifier.trim();
    if (normalized.isEmpty) {
      _activeUser = _defaultUser;
      return _defaultUser;
    }

    if (mode == AppMode.noAuth) {
      try {
        final response = await _client.fetchUserProfile(
          ClientUserProfileRequest(identifier: normalized),
          options: const ClientRequestOptions(headers: <String, String>{}),
        );
        final user = response == null ? _defaultUser : _toAppUser(response);
        _activeUser = user;
        return user;
      } catch (_) {
        _activeUser = _defaultUser;
        return _defaultUser;
      }
    }

    final response = await _client.fetchUserProfile(
      ClientUserProfileRequest(identifier: normalized),
      options: ClientRequestOptions(headers: await _authHeaders()),
    );
    final user = response == null ? _defaultUser : _toAppUser(response);
    _activeUser = user;
    return user;
  }

  Future<RegistrationResult> register({
    required String username,
    String email = '',
    String phone = '',
    required String password,
  }) {
    return _client
        .registerUser(
          ClientRegisterRequest(
            username: username,
            email: email,
            phone: phone,
            password: password,
          ),
        )
        .then(_toRegistrationResult);
  }

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

  Future<List<RecordStationOption>> fetchStationOptions() async {
    final response = await _client.listRecordStationOptions(
      const ClientRecordStationOptionsRequest(),
      options: ClientRequestOptions(headers: await _authHeaders()),
    );

    final stations = response.map(_toStationOption).toList(growable: false);
    _lastStationOptions = stations;
    return stations;
  }

  Future<RecordCursorPage> fetchRecordsByCursor({
    DateTimeRange? dateRange,
    String? stationId,
    String? cursor,
    int limit = 20,
  }) async {
    final response = await _client.listRecordsByCursor(
      ClientRecordsCursorRequest(
        startAtMs: dateRange?.start.millisecondsSinceEpoch,
        endAtMs: dateRange?.end.millisecondsSinceEpoch,
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

  Future<List<TrendPoint>> fetchWeeklyTrend({
    int days = 7,
    String? stationId,
  }) async {
    final response = await _client.getWeeklyTrend(
      ClientWeeklyTrendRequest(days: days, deviceId: stationId),
      options: ClientRequestOptions(headers: await _authHeaders()),
    );

    final points = response.series
        .map(
          (point) => TrendPoint(
            label: point.label,
            value: point.value,
            dateMs: point.dateMs,
          ),
        )
        .toList(growable: false);
    _lastWeeklyTrend = points;
    return points;
  }

  Future<RangeSummary> fetchRangeSummary({
    required DateTimeRange dateRange,
    String? stationId,
  }) async {
    final response = await _client.getRangeSummary(
      ClientRangeSummaryRequest(
        startAtMs: dateRange.start.millisecondsSinceEpoch,
        endAtMs: dateRange.end.millisecondsSinceEpoch,
        deviceId: stationId,
      ),
      options: ClientRequestOptions(headers: await _authHeaders()),
    );

    return _toRangeSummary(response);
  }

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
      if (!page.hasMore ||
          page.nextCursor == null ||
          page.nextCursor!.isEmpty) {
        break;
      }
      nextCursor = page.nextCursor;
    }

    _lastRecords = allRecords;
    return allRecords;
  }

  Future<void> signOut() async {
    _clearCachedState();
    await _credentials.clearSession();
    notifyListeners();
  }

  Future<Map<String, String>> _authHeaders() {
    return _credentials.buildAuthHeaders(refreshSession: _refreshSession);
  }

  Future<AuthSession> _refreshSession(AuthSession session) async {
    final refreshedCredentials = await _client.refreshSession(
      ClientRefreshSessionRequest(
        sessionId: session.credentials.sessionId?.trim() ?? '',
        refreshToken: session.credentials.refreshToken?.trim() ?? '',
        tokenId: session.credentials.tokenId?.trim() ?? '',
        tokenFamilyId: session.credentials.tokenFamilyId?.trim() ?? '',
        principalId: session.credentials.principalId?.trim() ?? '',
        scopes: session.credentials.scopes,
      ),
    );

    final refreshed = _toAuthSession(
      loginIdentifier: session.loginIdentifier,
      mode: session.mode,
      credentials: refreshedCredentials,
      signedInAt: session.signedInAt,
    );
    await _credentials.storeSession(refreshed);
    return refreshed;
  }

  void _clearCachedState() {
    _activeUser = _defaultUser;
    _loginIdentifier = null;
    _clearPageData();
  }

  void _clearPageData() {
    _lastDashboardSnapshot = null;
    _lastStationOptions = const [];
    _lastRecords = const [];
    _lastWeeklyTrend = const [];
    _lastSpeciesShares = const [];
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
      avatarB64: response.avatarB64,
    );
  }

  RegistrationResult _toRegistrationResult(ClientRegisterResponse response) {
    return RegistrationResult(
      ok: response.ok,
      errorCode: response.errorCode,
      message: response.message,
    );
  }

  DashboardSnapshot _toDashboardSnapshot(
    ClientDashboardSnapshotResponse response,
  ) {
    return DashboardSnapshot(
      todayRecognitionCount: response.todayRecognitionCount,
      todayUploadCount: response.todayUploadCount,
      onlineStationCount: response.onlineStationCount,
      activeStationCount: response.activeStationCount,
      topUploadStation: _toUploadStationSummary(response.topUploadStation),
      latestUpload: _toLatestUploadSummary(response.latestUpload),
      recentRecords: response.recentRecords
          .map(_toBirdRecord)
          .toList(growable: false),
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

  RecordStationOption _toStationOption(
    ClientRecordStationOptionResponse response,
  ) {
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
      capturedAtTime: DateTime.fromMillisecondsSinceEpoch(
        response.capturedAtMs,
      ),
      stationName: response.deviceName.isNotEmpty
          ? response.deviceName
          : response.deviceId,
      capturedAt: response.capturedAtLabel,
      confidence: response.confidence,
      temperature: response.temperatureC ?? 0.0,
      humidity: response.humidityPct ?? 0,
      uploadSummary: response.uploadSummary,
      speciesIntro: response.speciesIntro,
      imageB64: response.imageB64,
      accent: _accentFor(response),
      deviceId: response.deviceId,
      deviceName: response.deviceName,
      speciesEntityId: response.speciesEntityId.isEmpty
          ? null
          : response.speciesEntityId,
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

  AuthSession _toAuthSession({
    required String loginIdentifier,
    required AppMode mode,
    required ClientAuthCredentialsResponse credentials,
    required DateTime signedInAt,
  }) {
    return AuthSession(
      loginIdentifier: loginIdentifier,
      credentials: AuthCredentials(
        accessToken: credentials.accessToken,
        refreshToken: credentials.refreshToken,
        downstreamToken: credentials.downstreamToken,
        tokenType: credentials.tokenType,
        sessionId: credentials.sessionId,
        tokenId: credentials.tokenId,
        principalId: credentials.principalId,
        tokenFamilyId: credentials.tokenFamilyId,
        scopes: credentials.scopes,
        issuedAtMs: credentials.issuedAtMs,
        accessExpiresAtMs: credentials.accessExpiresAtMs,
        refreshExpiresAtMs: credentials.refreshExpiresAtMs,
        persisted: credentials.persisted,
      ),
      mode: mode,
      signedInAt: signedInAt,
    );
  }

  RangeSummary _toRangeSummary(ClientRangeSummaryResponse response) {
    final palette = <Color>[
      const Color(0xFF0B7A75),
      const Color(0xFF125D98),
      const Color(0xFFC97C1D),
      const Color(0xFF6D597A),
      const Color(0xFF2A9D8F),
      const Color(0xFFE76F51),
    ];

    final speciesShares = response.speciesShares.map((share) {
      final hash = share.label.hashCode.abs();
      return SpeciesShare(
        label: share.label,
        value: share.value,
        color: palette[hash % palette.length],
        speciesEntityId: share.speciesEntityId.isEmpty
            ? null
            : share.speciesEntityId,
      );
    }).toList(growable: false);

    return RangeSummary(
      totalCount: response.totalCount,
      dailyDistribution: response.dailyDistribution
          .map(
            (point) => TrendPoint(
              label: point.label,
              value: point.value,
              dateMs: point.dateMs,
            ),
          )
          .toList(growable: false),
      speciesShares: speciesShares,
      peakDay: _toPeakDay(response.peakDay),
      peakDevice: _toPeakDevice(response.peakDevice),
    );
  }

  PeakDaySummary _toPeakDay(ClientPeakDayResponse response) {
    return PeakDaySummary(
      label: response.label,
      value: response.value,
      dateMs: response.dateMs,
    );
  }

  PeakDeviceSummary _toPeakDevice(ClientPeakDeviceSummaryResponse response) {
    return PeakDeviceSummary(
      deviceId: response.deviceId,
      deviceName: response.deviceName,
      recordCount: response.recordCount,
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
