import 'package:flutter/material.dart';

import 'package:bms_app/models/common.dart';

class MockClientRepository {
  MockClientRepository();

  static const Map<String, String> _stationDeviceIds = {
    '南湖湿地站': '8c0a2c1d-0b1f-4e56-b3e2-11a5f0b6b001',
    '东堤观察点': '8c0a2c1d-0b1f-4e56-b3e2-11a5f0b6b002',
    '北岸瞭望台': '8c0a2c1d-0b1f-4e56-b3e2-11a5f0b6b003',
    '西侧林缘点': '8c0a2c1d-0b1f-4e56-b3e2-11a5f0b6b004',
  };

  final List<AppUser> _users = [
    const AppUser(
      name: '测试用户',
      role: '系统演示账号',
      phone: '138-0000-0000',
      avatarSeed: 7,
      userId: '7a4a7c0c-6b12-4d5f-9a8f-7b2a12d02f19',
      username: 'demo_user',
      displayName: '测试用户',
      email: 'demo_user@example.com',
    ),
    const AppUser(
      name: '巡护员张三',
      role: '现场巡护账号',
      phone: '139-1111-2222',
      avatarSeed: 19,
      userId: '9c6a7e2c-2c4d-4d5c-96b2-53f7b5b2d921',
      username: 'zhangsan',
      displayName: '巡护员张三',
      email: 'zhangsan@example.com',
    ),
  ];

  late final List<BirdRecord> _records = _buildSeedRecords();

  AppUser get defaultUser => _users.first;

  AppUser? findUserByIdentifier(String identifier) {
    final normalized = identifier.trim().toLowerCase();
    if (normalized.isEmpty) {
      return defaultUser;
    }

    final normalizedPhone = _normalizePhone(identifier);
    for (final user in _users) {
      if ((user.username ?? '').trim().toLowerCase() == normalized ||
          (user.email ?? '').trim().toLowerCase() == normalized ||
          _normalizePhone(user.phone) == normalizedPhone) {
        return user;
      }
    }
    return null;
  }

  RegistrationResult registerUser({
    required String username,
    String email = '',
    String phone = '',
    required String password,
  }) {
    final normalizedUsername = username.trim().toLowerCase();
    final normalizedEmail = email.trim().toLowerCase();
    final normalizedPhone = _normalizePhone(phone);

    if (normalizedUsername.isEmpty || password.trim().length < 6) {
      return const RegistrationResult(
        ok: false,
        errorCode: RegistrationErrorCode.invalidData,
        message: '注册信息不完整',
      );
    }

    for (final user in _users) {
      if ((user.username ?? '').trim().toLowerCase() == normalizedUsername) {
        return const RegistrationResult(
          ok: false,
          errorCode: RegistrationErrorCode.usernameExists,
          message: '用户名已存在',
        );
      }
      if (normalizedEmail.isNotEmpty &&
          (user.email ?? '').trim().toLowerCase() == normalizedEmail) {
        return const RegistrationResult(
          ok: false,
          errorCode: RegistrationErrorCode.emailExists,
          message: '邮箱已存在',
        );
      }
      if (normalizedPhone.isNotEmpty && _normalizePhone(user.phone) == normalizedPhone) {
        return const RegistrationResult(
          ok: false,
          errorCode: RegistrationErrorCode.phoneExists,
          message: '手机号已存在',
        );
      }
    }

    _users.add(
      AppUser(
        name: username.trim(),
        role: '注册用户',
        phone: phone.trim(),
        avatarSeed: normalizedUsername.hashCode.abs() % 100,
        userId: 'mock-${normalizedUsername.hashCode.abs()}',
        username: normalizedUsername,
        displayName: username.trim(),
        email: email.trim(),
      ),
    );

    return const RegistrationResult(ok: true, message: '注册成功');
  }

  DashboardSnapshot buildDashboardSnapshot() {
    final latestDay = _latestRecordDay();
    final todayRecords = _recordsOnDay(latestDay);
    final countsByStation = <String, int>{};
    for (final record in todayRecords) {
      countsByStation[record.stationName] = (countsByStation[record.stationName] ?? 0) + 1;
    }

    final topEntry = countsByStation.entries.isEmpty
        ? null
        : countsByStation.entries.reduce((left, right) {
            return left.value >= right.value ? left : right;
          });

    final latestRecord = _records.reduce((left, right) {
      return left.capturedAtTime.isAfter(right.capturedAtTime) ? left : right;
    });

    final activeStationCount = _records.map((record) => record.stationName).toSet().length;

    return DashboardSnapshot(
      todayRecognitionCount: todayRecords.length,
      todayUploadCount: todayRecords.length,
      onlineStationCount: _stationDeviceIds.length,
      activeStationCount: activeStationCount,
      topUploadStation: UploadStationSummary(
        deviceId: topEntry == null ? '' : (_stationDeviceIds[topEntry.key] ?? ''),
        deviceName: topEntry?.key ?? '暂无数据',
        uploadCount: topEntry?.value ?? 0,
      ),
      latestUpload: LatestUploadSummary(
        deviceId: latestRecord.deviceIdValue,
        deviceName: latestRecord.deviceNameValue,
        uploadedAtLabel: latestRecord.capturedAt,
        uploadedAtMs: latestRecord.capturedAtMsValue,
      ),
      recentRecords: (_sortedRecords()..sort((a, b) => b.capturedAtTime.compareTo(a.capturedAtTime)))
          .take(3)
          .toList(growable: false),
    );
  }

  List<RecordStationOption> listStationOptions() {
    return _stationDeviceIds.entries
        .map(
          (entry) => RecordStationOption(deviceId: entry.value, deviceName: entry.key),
        )
        .toList(growable: false);
  }

  RecordCursorPage listRecordsByCursor({
    DateTimeRange? dateRange,
    String? stationId,
    String? cursor,
    int limit = 20,
  }) {
    final filtered = listRecords(dateRange: dateRange, stationId: stationId);
    final start = _decodeCursor(cursor).clamp(0, filtered.length);
    final end = (start + (limit <= 0 ? 20 : limit)).clamp(0, filtered.length);

    return RecordCursorPage(
      items: filtered.sublist(start, end),
      nextCursor: end < filtered.length ? '$end' : null,
      hasMore: end < filtered.length,
    );
  }

  List<BirdRecord> listRecords({
    DateTimeRange? dateRange,
    String? stationId,
  }) {
    final sorted = _sortedRecords();
    return sorted.where((record) {
      final stationMatch = stationId == null || stationId.isEmpty || record.deviceIdValue == stationId;
      final dateMatch = dateRange == null || _recordInRange(record, dateRange);
      return stationMatch && dateMatch;
    }).toList(growable: false);
  }

  List<TrendPoint> weeklyTrend({
    int days = 7,
    String? stationId,
  }) {
    final normalizedDays = days <= 0 ? 7 : days;
    final latest = _latestRecordDay();
    final start = latest.subtract(Duration(days: normalizedDays - 1));

    final countsByDay = <DateTime, int>{};
    for (final record in _records) {
      if (stationId != null && stationId.isNotEmpty && record.deviceIdValue != stationId) {
        continue;
      }
      final day = DateUtils.dateOnly(record.capturedAtTime);
      countsByDay[day] = (countsByDay[day] ?? 0) + 1;
    }

    final points = <TrendPoint>[];
    for (var day = start; !day.isAfter(latest); day = day.add(const Duration(days: 1))) {
      points.add(
        TrendPoint(
          label: _weekdayLabel(day.weekday),
          value: countsByDay[day] ?? 0,
          dateMs: day.millisecondsSinceEpoch,
        ),
      );
    }
    return points;
  }

  List<BirdRecord> _recordsOnDay(DateTime day) {
    final start = DateUtils.dateOnly(day);
    final endExclusive = start.add(const Duration(days: 1));
    return _records.where((record) {
      return !record.capturedAtTime.isBefore(start) && record.capturedAtTime.isBefore(endExclusive);
    }).toList(growable: false);
  }

  DateTime _latestRecordDay() {
    final latest = _records.reduce((left, right) {
      return left.capturedAtTime.isAfter(right.capturedAtTime) ? left : right;
    });
    return DateUtils.dateOnly(latest.capturedAtTime);
  }

  List<BirdRecord> _sortedRecords() {
    final records = [..._records];
    records.sort((left, right) => right.capturedAtTime.compareTo(left.capturedAtTime));
    return records;
  }

  bool _recordInRange(BirdRecord record, DateTimeRange dateRange) {
    final start = DateUtils.dateOnly(dateRange.start);
    final endExclusive = DateUtils.dateOnly(dateRange.end).add(const Duration(days: 1));
    return !record.capturedAtTime.isBefore(start) && record.capturedAtTime.isBefore(endExclusive);
  }

  int _decodeCursor(String? cursor) {
    if (cursor == null || cursor.trim().isEmpty) {
      return 0;
    }
    final parsed = int.tryParse(cursor.trim());
    if (parsed == null || parsed < 0) {
      return 0;
    }
    return parsed;
  }

  String _normalizePhone(String value) => value.replaceAll(RegExp(r'\D'), '');

  String _weekdayLabel(int weekday) {
    return switch (weekday) {
      DateTime.monday => '周一',
      DateTime.tuesday => '周二',
      DateTime.wednesday => '周三',
      DateTime.thursday => '周四',
      DateTime.friday => '周五',
      DateTime.saturday => '周六',
      DateTime.sunday => '周日',
      _ => '未知',
    };
  }

  List<BirdRecord> _buildSeedRecords() {
    return [
      _record(
        id: 'R-2401',
        species: '白鹭',
        scientificName: 'Egretta garzetta',
        capturedAtTime: DateTime(2026, 4, 11, 9, 20),
        stationName: '南湖湿地站',
        confidence: 0.97,
        temperature: 18.4,
        humidity: 64,
      ),
      _record(
        id: 'R-2402',
        species: '灰鹭',
        scientificName: 'Ardea cinerea',
        capturedAtTime: DateTime(2026, 4, 11, 8, 45),
        stationName: '东堤观察点',
        confidence: 0.94,
        temperature: 17.8,
        humidity: 68,
      ),
      _record(
        id: 'R-2403',
        species: '夜鹭',
        scientificName: 'Nycticorax nycticorax',
        capturedAtTime: DateTime(2026, 4, 10, 18, 30),
        stationName: '北岸瞭望台',
        confidence: 0.91,
        temperature: 18.6,
        humidity: 66,
      ),
      _record(
        id: 'R-2404',
        species: '苍鹭',
        scientificName: 'Ardea alba',
        capturedAtTime: DateTime(2026, 4, 10, 17, 58),
        stationName: '西侧林缘点',
        confidence: 0.89,
        temperature: 20.1,
        humidity: 59,
      ),
      _record(
        id: 'R-2405',
        species: '白鹭',
        scientificName: 'Egretta garzetta',
        capturedAtTime: DateTime(2026, 4, 9, 18, 12),
        stationName: '南湖湿地站',
        confidence: 0.96,
        temperature: 18.6,
        humidity: 63,
      ),
      _record(
        id: 'R-2406',
        species: '灰鹭',
        scientificName: 'Ardea cinerea',
        capturedAtTime: DateTime(2026, 4, 9, 14, 50),
        stationName: '东堤观察点',
        confidence: 0.92,
        temperature: 19.2,
        humidity: 58,
      ),
      _record(
        id: 'R-2407',
        species: '夜鹭',
        scientificName: 'Nycticorax nycticorax',
        capturedAtTime: DateTime(2026, 4, 8, 7, 36),
        stationName: '北岸瞭望台',
        confidence: 0.90,
        temperature: 16.8,
        humidity: 74,
      ),
      _record(
        id: 'R-2408',
        species: '苍鹭',
        scientificName: 'Ardea alba',
        capturedAtTime: DateTime(2026, 4, 8, 11, 12),
        stationName: '西侧林缘点',
        confidence: 0.87,
        temperature: 17.5,
        humidity: 70,
      ),
      _record(
        id: 'R-2409',
        species: '白鹭',
        scientificName: 'Egretta garzetta',
        capturedAtTime: DateTime(2026, 4, 7, 6, 58),
        stationName: '南湖湿地站',
        confidence: 0.98,
        temperature: 15.9,
        humidity: 77,
      ),
      _record(
        id: 'R-2410',
        species: '灰鹭',
        scientificName: 'Ardea cinerea',
        capturedAtTime: DateTime(2026, 4, 6, 17, 5),
        stationName: '北岸瞭望台',
        confidence: 0.88,
        temperature: 18.1,
        humidity: 62,
      ),
      _record(
        id: 'R-2411',
        species: '夜鹭',
        scientificName: 'Nycticorax nycticorax',
        capturedAtTime: DateTime(2026, 4, 5, 19, 14),
        stationName: '东堤观察点',
        confidence: 0.90,
        temperature: 17.6,
        humidity: 67,
      ),
      _record(
        id: 'R-2412',
        species: '苍鹭',
        scientificName: 'Ardea alba',
        capturedAtTime: DateTime(2026, 4, 4, 10, 33),
        stationName: '西侧林缘点',
        confidence: 0.89,
        temperature: 18.3,
        humidity: 61,
      ),
    ];
  }

  BirdRecord _record({
    required String id,
    required String species,
    required String scientificName,
    required DateTime capturedAtTime,
    required String stationName,
    required double confidence,
    required double temperature,
    required int humidity,
  }) {
    final day = capturedAtTime.day.toString().padLeft(2, '0');
    final month = capturedAtTime.month.toString().padLeft(2, '0');
    final hour = capturedAtTime.hour.toString().padLeft(2, '0');
    final minute = capturedAtTime.minute.toString().padLeft(2, '0');

    return BirdRecord(
      id: id,
      recordId: id,
      species: species,
      scientificName: scientificName,
      capturedAtTime: capturedAtTime,
      stationName: stationName,
      capturedAt: '${capturedAtTime.year}-$month-$day $hour:$minute',
      confidence: confidence,
      temperature: temperature,
      humidity: humidity,
      uploadSummary: '设备自动上传 · 识别结果已同步至业务库',
      speciesIntro: '$species（$scientificName）常见于湿地与湖岸生态系统。',
      accent: _accentFor(species),
      deviceId: _stationDeviceIds[stationName],
      deviceName: stationName,
      speciesEntityId: 'species-${species.hashCode.abs()}',
      capturedAtMs: capturedAtTime.millisecondsSinceEpoch,
      temperatureC: temperature,
      humidityPct: humidity,
      mediaRefs: const [],
      processingSource: 'edge',
      modelVersion: 'demo-v1',
      recordStatus: 'published',
      summaryText: '设备自动上传 · 识别结果已同步至业务库',
    );
  }

  Color _accentFor(String species) {
    return switch (species) {
      '白鹭' => const Color(0xFF2A9D8F),
      '灰鹭' => const Color(0xFFE76F51),
      '夜鹭' => const Color(0xFF3D5A80),
      '苍鹭' => const Color(0xFF8D99AE),
      _ => const Color(0xFF0B7A75),
    };
  }
}
