import 'package:flutter/material.dart';

import 'package:bms_app/mock_repo/mock_repository.dart';
import 'package:bms_app/models/api_models.dart';
import 'package:bms_app/models/common.dart';
import 'package:bms_app/models/transport/client_req_dto.dart';
import 'package:bms_app/models/transport/client_resp_dto.dart';
import 'package:bms_app/transport/transport_client.dart';

class MockMonitoringClient implements MonitoringClient {
  MockMonitoringClient({MockClientRepository? repository})
    : _repository = repository ?? MockClientRepository();

  final MockClientRepository _repository;

  @override
  Future<ClientAuthCredentialsResponse> signIn(
    ClientSignInRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  }) async {
    final now = DateTime.now();
    final seed = request.password.trim().isEmpty
        ? 'blank'
        : request.password.trim().hashCode.toUnsigned(32).toRadixString(16);

    return ClientAuthCredentialsResponse(
      accessToken: 'mock-access-${now.millisecondsSinceEpoch}-$seed',
      refreshToken: 'mock-refresh-${now.millisecondsSinceEpoch}-$seed',
      downstreamToken: 'mock-downstream-${now.millisecondsSinceEpoch}-$seed',
      tokenType: 'access',
      sessionId: 'mock-session-${now.millisecondsSinceEpoch}',
      tokenId: 'mock-token-${now.microsecondsSinceEpoch}',
      principalId: request.identifier.trim().isEmpty
          ? 'demo_user'
          : request.identifier.trim(),
      tokenFamilyId: 'mock-family-${now.millisecondsSinceEpoch}',
      scopes: const ['client:read', 'client:write'],
      issuedAtMs: now.millisecondsSinceEpoch,
      accessExpiresAtMs: now
          .add(const Duration(hours: 2))
          .millisecondsSinceEpoch,
      refreshExpiresAtMs: now
          .add(const Duration(days: 30))
          .millisecondsSinceEpoch,
      persisted: true,
    );
  }

  @override
  Future<ClientAuthCredentialsResponse> refreshSession(
    ClientRefreshSessionRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  }) async {
    if (request.refreshToken.trim().isEmpty) {
      throw const ClientHttpException(
        statusCode: 401,
        message: 'refresh token missing',
        path: '/mock/auth/refresh-session',
      );
    }

    final now = DateTime.now();
    return ClientAuthCredentialsResponse(
      accessToken: 'mock-access-refreshed-${now.millisecondsSinceEpoch}',
      refreshToken: 'mock-refresh-refreshed-${now.millisecondsSinceEpoch}',
      downstreamToken:
          'mock-downstream-refreshed-${now.millisecondsSinceEpoch}',
      tokenType: 'access',
      sessionId: request.sessionId.trim().isEmpty
          ? 'mock-session-${now.millisecondsSinceEpoch}'
          : request.sessionId.trim(),
      tokenId: 'mock-token-${now.microsecondsSinceEpoch}',
      principalId: request.principalId.trim().isEmpty
          ? 'demo_user'
          : request.principalId.trim(),
      tokenFamilyId: request.tokenFamilyId.trim().isEmpty
          ? 'mock-family-${now.millisecondsSinceEpoch}'
          : request.tokenFamilyId.trim(),
      scopes: request.scopes.isEmpty
          ? const ['client:read', 'client:write']
          : request.scopes,
      issuedAtMs: now.millisecondsSinceEpoch,
      accessExpiresAtMs: now
          .add(const Duration(hours: 2))
          .millisecondsSinceEpoch,
      refreshExpiresAtMs: now
          .add(const Duration(days: 30))
          .millisecondsSinceEpoch,
      persisted: true,
    );
  }

  @override
  Future<ClientUserProfileResponse?> fetchUserProfile(
    ClientUserProfileRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  }) async {
    final user = _repository.findUserByIdentifier(request.identifier);
    if (user == null) {
      return null;
    }
    return _toUserProfile(user);
  }

  @override
  Future<ClientRegisterResponse> registerUser(
    ClientRegisterRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  }) async {
    final result = _repository.registerUser(
      username: request.username,
      email: request.email,
      phone: request.phone,
      password: request.password,
    );
    return ClientRegisterResponse(
      ok: result.ok,
      errorCode: result.errorCode,
      message: result.message,
    );
  }

  @override
  Future<ClientDashboardSnapshotResponse> fetchDashboardSnapshot(
    ClientHomeSnapshotRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  }) async {
    final snapshot = _repository.buildDashboardSnapshot();
    return ClientDashboardSnapshotResponse(
      todayRecognitionCount: snapshot.todayRecognitionCount,
      todayUploadCount: snapshot.todayUploadCount,
      onlineStationCount: snapshot.onlineStationCount,
      activeStationCount: snapshot.activeStationCount,
      topUploadStation: ClientUploadStationSummaryResponse(
        deviceId: snapshot.topUploadStation.deviceId,
        deviceName: snapshot.topUploadStation.deviceName,
        uploadCount: snapshot.topUploadStation.uploadCount,
      ),
      latestUpload: ClientLatestUploadSummaryResponse(
        deviceId: snapshot.latestUpload.deviceId,
        deviceName: snapshot.latestUpload.deviceName,
        uploadedAtMs: snapshot.latestUpload.uploadedAtMs,
        uploadedAtLabel: snapshot.latestUpload.uploadedAtLabel,
      ),
      recentRecords: snapshot.recentRecords
          .map(_toBirdRecordResponse)
          .toList(growable: false),
    );
  }

  @override
  Future<List<ClientRecordStationOptionResponse>> listRecordStationOptions(
    ClientRecordStationOptionsRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  }) async {
    final optionsList = _repository.listStationOptions();
    return optionsList
        .map(
          (option) => ClientRecordStationOptionResponse(
            deviceId: option.deviceId,
            deviceName: option.deviceName,
            online: true,
            status: 'online',
          ),
        )
        .toList(growable: false);
  }

  @override
  Future<ClientRecordsCursorResponse> listRecordsByCursor(
    ClientRecordsCursorRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  }) async {
    final dateRange = _toDateRange(request.startAtMs, request.endAtMs);
    final page = _repository.listRecordsByCursor(
      dateRange: dateRange,
      stationId: request.deviceId,
      cursor: request.cursor,
      limit: request.limit,
    );

    return ClientRecordsCursorResponse(
      items: page.items.map(_toBirdRecordResponse).toList(growable: false),
      nextCursor: page.nextCursor ?? '',
      hasMore: page.hasMore,
    );
  }

  @override
  Future<ClientWeeklyTrendResponse> getWeeklyTrend(
    ClientWeeklyTrendRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  }) async {
    final points = _repository.weeklyTrend(
      days: request.days,
      stationId: request.deviceId,
    );

    final total = points.fold<int>(
      0,
      (current, point) => current + point.value,
    );
    return ClientWeeklyTrendResponse(
      series: points
          .map(
            (point) => ClientTrendPointResponse(
              label: point.label,
              value: point.value,
              dateMs: point.dateMs,
            ),
          )
          .toList(growable: false),
      total: total,
    );
  }

  @override
  Future<ClientRangeSummaryResponse> getRangeSummary(
    ClientRangeSummaryRequest request, {
    ClientRequestOptions options = const ClientRequestOptions(),
  }) async {
    final dateRange = _toDateRange(request.startAtMs, request.endAtMs);
    final records = _repository.listRecords(
      dateRange: dateRange,
      stationId: request.deviceId,
    );

    final distribution = _buildDailyDistribution(records, dateRange);
    final speciesShares = _buildSpeciesShares(records);
    final peakPoint = distribution.isEmpty
        ? null
        : distribution.reduce(
            (left, right) => left.value >= right.value ? left : right,
          );
    final peakDay = peakPoint == null
        ? const ClientPeakDayResponse(label: '-', value: 0)
        : ClientPeakDayResponse(
            label: peakPoint.label,
            value: peakPoint.value,
            dateMs: peakPoint.dateMs,
          );
    final peakDevice = _buildPeakDevice(records);

    return ClientRangeSummaryResponse(
      totalCount: records.length,
      dailyDistribution: distribution,
      speciesShares: speciesShares,
      peakDay: peakDay,
      peakDevice: peakDevice,
    );
  }

  DateTimeRange _toDateRange(int? startAtMs, int? endAtMs) {
    if (startAtMs == null || endAtMs == null) {
      final latest = DateUtils.dateOnly(DateTime.now());
      return DateTimeRange(
        start: latest.subtract(const Duration(days: 6)),
        end: latest,
      );
    }

    final start = DateTime.fromMillisecondsSinceEpoch(startAtMs);
    final end = DateTime.fromMillisecondsSinceEpoch(endAtMs);
    return DateTimeRange(start: start, end: end);
  }

  List<ClientTrendPointResponse> _buildDailyDistribution(
    List<BirdRecord> records,
    DateTimeRange range,
  ) {
    final start = DateUtils.dateOnly(range.start);
    final end = DateUtils.dateOnly(range.end);
    final counts = <DateTime, int>{};
    for (final record in records) {
      final day = DateUtils.dateOnly(record.capturedAtTime);
      counts[day] = (counts[day] ?? 0) + 1;
    }

    final result = <ClientTrendPointResponse>[];
    for (
      var day = start;
      !day.isAfter(end);
      day = day.add(const Duration(days: 1))
    ) {
      result.add(
        ClientTrendPointResponse(
          label: '${day.month}/${day.day}',
          value: counts[day] ?? 0,
          dateMs: day.millisecondsSinceEpoch,
        ),
      );
    }
    return result;
  }

  List<ClientSpeciesShareResponse> _buildSpeciesShares(
    List<BirdRecord> records,
  ) {
    if (records.isEmpty) {
      return const [];
    }

    final total = records.length;
    final counts = <String, int>{};
    final accents = <String, Color>{};
    for (final record in records) {
      counts[record.species] = (counts[record.species] ?? 0) + 1;
      accents.putIfAbsent(record.species, () => record.accent);
    }

    return counts.entries
        .map(
          (entry) => ClientSpeciesShareResponse(
            label: entry.key,
            value: entry.value,
            ratio: entry.value / total,
            speciesEntityId: 'species-${entry.key.hashCode.abs()}',
            colorHex: _colorHex(accents[entry.key] ?? const Color(0xFF0B7A75)),
          ),
        )
        .toList(growable: false);
  }

  ClientPeakDeviceSummaryResponse _buildPeakDevice(List<BirdRecord> records) {
    if (records.isEmpty) {
      return const ClientPeakDeviceSummaryResponse(
        deviceId: '',
        deviceName: '-',
        recordCount: 0,
      );
    }

    final counts = <String, int>{};
    final names = <String, String>{};
    for (final record in records) {
      final deviceId = record.deviceIdValue;
      counts[deviceId] = (counts[deviceId] ?? 0) + 1;
      names[deviceId] = record.deviceNameValue;
    }

    final peak = counts.entries.reduce((left, right) {
      return left.value >= right.value ? left : right;
    });
    return ClientPeakDeviceSummaryResponse(
      deviceId: peak.key,
      deviceName: names[peak.key] ?? peak.key,
      recordCount: peak.value,
    );
  }

  ClientBirdRecordResponse _toBirdRecordResponse(BirdRecord record) {
    return ClientBirdRecordResponse(
      id: record.recordIdValue,
      species: record.species,
      scientificName: record.scientificName,
      capturedAtMs: record.capturedAtMsValue,
      capturedAtLabel: record.capturedAt,
      deviceId: record.deviceIdValue,
      deviceName: record.deviceNameValue,
      confidence: record.confidence,
      temperatureC: record.temperatureCValue,
      humidityPct: record.humidityPctValue,
      uploadSummary: record.uploadSummary,
      speciesIntro: record.speciesIntro,
      imageB64: record.imageB64,
      mediaRefs: record.mediaRefs,
      processingSource: record.processingSource,
      modelVersion: record.modelVersion,
      recordStatus: record.recordStatus,
      summaryText: record.summaryTextValue,
      speciesEntityId: record.speciesEntityId ?? '',
      metadata: const {},
    );
  }

  ClientUserProfileResponse _toUserProfile(AppUser user) {
    return ClientUserProfileResponse(
      userId: user.userId ?? '',
      username: user.username ?? '',
      displayName: user.displayNameValue,
      name: user.name,
      role: user.role,
      email: user.email ?? '',
      phone: user.phone,
      avatarB64: user.avatarB64,
    );
  }

  String _colorHex(Color color) {
    final value = color.toARGB32();
    final rgb = value & 0x00FFFFFF;
    return '#${rgb.toRadixString(16).padLeft(6, '0').toUpperCase()}';
  }
}
