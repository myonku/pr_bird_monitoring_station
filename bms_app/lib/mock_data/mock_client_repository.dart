import 'package:flutter/material.dart';

import 'package:bms_app/data_source/monitoring_repository.dart';
import 'package:bms_app/models/monitoring_models.dart';

class MockClientRepository implements MonitoringRepository {
  const MockClientRepository();

  static final List<String> _stations = ['南湖湿地站', '东堤观察点', '北岸瞭望台', '西侧林缘点'];
  static const Map<String, String> _stationDeviceIds = {
    '南湖湿地站': '8c0a2c1d-0b1f-4e56-b3e2-11a5f0b6b001',
    '东堤观察点': '8c0a2c1d-0b1f-4e56-b3e2-11a5f0b6b002',
    '北岸瞭望台': '8c0a2c1d-0b1f-4e56-b3e2-11a5f0b6b003',
    '西侧林缘点': '8c0a2c1d-0b1f-4e56-b3e2-11a5f0b6b004',
  };

  static final List<AppUser> _users = [
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

  AppUser? _lookupUser(bool Function(AppUser user) predicate) {
    for (final user in _users) {
      if (predicate(user)) {
        return user;
      }
    }
    return null;
  }

  static String _normalizeText(String value) => value.trim().toLowerCase();

  static String _normalizePhone(String value) =>
      value.replaceAll(RegExp(r'\D'), '');

  DateTime _latestRecordDay() {
    return records
        .map((record) => DateUtils.dateOnly(record.capturedAtTime))
        .reduce((current, next) => current.isAfter(next) ? current : next);
  }

  List<BirdRecord> _recordsOnDay(DateTime day) {
    final dayOnly = DateUtils.dateOnly(day);
    final nextDay = dayOnly.add(const Duration(days: 1));
    return records.where((record) {
      return !record.capturedAtTime.isBefore(dayOnly) &&
          record.capturedAtTime.isBefore(nextDay);
    }).toList();
  }

  @override
  int countTodayMonitoringRecords() => _recordsOnDay(_latestRecordDay()).length;

  @override
  int countTodayUploadRecords() => _recordsOnDay(_latestRecordDay()).length;

  @override
  int countOnlineStations() => _stations.length;

  @override
  UploadStationSummary getTodayTopUploadStation() {
    final todayRecords = _recordsOnDay(_latestRecordDay());
    final counts = <String, int>{};
    for (final record in todayRecords) {
      counts[record.stationName] = (counts[record.stationName] ?? 0) + 1;
    }

    if (counts.isEmpty) {
      return const UploadStationSummary(
        deviceId: '',
        deviceName: '暂无数据',
        uploadCount: 0,
      );
    }

    final entry = counts.entries.reduce(
      (current, next) => current.value >= next.value ? current : next,
    );
    final deviceId = _stationDeviceIds[entry.key] ?? '';
    return UploadStationSummary(
      deviceId: deviceId,
      deviceName: entry.key,
      uploadCount: entry.value,
    );
  }

  @override
  LatestUploadSummary getLatestUploadSummary() {
    final latest = records.reduce(
      (current, next) => current.capturedAtTime.isAfter(next.capturedAtTime)
          ? current
          : next,
    );
    return LatestUploadSummary(
      deviceId: latest.deviceIdValue,
      deviceName: latest.deviceNameValue,
      uploadedAtLabel: latest.capturedAt,
      uploadedAtMs: latest.capturedAtMs,
    );
  }

  @override
  Future<DashboardSnapshot> fetchDashboardSnapshot() async {
    final activeStationCount = records
        .map((record) => record.stationName)
        .toSet()
        .length;

    return DashboardSnapshot(
      todayRecognitionCount: countTodayMonitoringRecords(),
      todayUploadCount: countTodayUploadRecords(),
      onlineStationCount: countOnlineStations(),
      activeStationCount: activeStationCount,
      topUploadStation: getTodayTopUploadStation(),
      latestUpload: getLatestUploadSummary(),
      recentRecords: getRecentRecords(limit: 3),
    );
  }

  List<BirdRecord> getRecentRecords({int limit = 3}) {
    final sortedRecords = [...records]
      ..sort((left, right) => right.capturedAtTime.compareTo(left.capturedAtTime));
    return sortedRecords.take(limit).toList();
  }

  @override
  AppUser get defaultUser => const AppUser(
    name: '测试用户',
    role: '系统演示账号',
    phone: '138-0000-0000',
    avatarSeed: 7,
    userId: '7a4a7c0c-6b12-4d5f-9a8f-7b2a12d02f19',
    username: 'demo_user',
    displayName: '测试用户',
    email: 'demo_user@example.com',
  );

  @override
  Future<AppUser?> fetchUserProfile(String identifier) async {
    final normalized = _normalizeText(identifier);
    if (normalized.isEmpty) {
      return defaultUser;
    }

    return _lookupUser(
      (user) =>
          _normalizeText(user.username ?? '') == normalized ||
          _normalizeText(user.email ?? '') == normalized ||
          _normalizePhone(user.phone) == _normalizePhone(identifier),
    );
  }

  @override
  Future<RegistrationResult> registerUser({
    required String username,
    String email = '',
    String phone = '',
    required String password,
  }) async {
    final normalizedUsername = _normalizeText(username);
    final normalizedEmail = _normalizeText(email);
    final normalizedPhone = _normalizePhone(phone);
    final trimmedPassword = password.trim();

    if (normalizedUsername.isEmpty || trimmedPassword.length < 6) {
      return const RegistrationResult(
        ok: false,
        errorCode: RegistrationErrorCode.invalidData,
        message: '注册信息不完整',
      );
    }

    final usernameExists = _lookupUser(
      (user) => _normalizeText(user.username ?? '') == normalizedUsername,
    );
    if (usernameExists != null) {
      return const RegistrationResult(
        ok: false,
        errorCode: RegistrationErrorCode.usernameExists,
        message: '用户名已存在',
      );
    }

    if (normalizedEmail.isNotEmpty) {
      final emailExists = _lookupUser(
        (user) => _normalizeText(user.email ?? '') == normalizedEmail,
      );
      if (emailExists != null) {
        return const RegistrationResult(
          ok: false,
          errorCode: RegistrationErrorCode.emailExists,
          message: '邮箱已存在',
        );
      }
    }

    if (normalizedPhone.isNotEmpty) {
      final phoneExists = _lookupUser(
        (user) => _normalizePhone(user.phone) == normalizedPhone,
      );
      if (phoneExists != null) {
        return const RegistrationResult(
          ok: false,
          errorCode: RegistrationErrorCode.phoneExists,
          message: '手机号已存在',
        );
      }
    }

    final displayName = username.trim();
    final newUser = AppUser(
      name: displayName,
      role: '注册用户',
      phone: phone.trim(),
      avatarSeed: normalizedUsername.hashCode.abs() % 100,
      userId: 'mock-${normalizedUsername.hashCode.abs().toString()}',
      username: normalizedUsername,
      displayName: displayName,
      email: email.trim(),
    );
    _users.add(newUser);

    return const RegistrationResult(
      ok: true,
      message: '注册成功',
    );
  }

  @override
  List<BirdRecord> get records => [
    _record(
      id: 'R-2401',
      species: '白鹭',
      scientificName: 'Egretta garzetta',
      capturedAtTime: DateTime(2026, 4, 11, 9, 20),
      stationName: '南湖湿地站',
      capturedAt: '2026-04-11 09:20',
      confidence: 0.97,
      temperature: 18.4,
      humidity: 64,
      uploadSummary: '设备自动上传 · 识别结果已同步至业务库',
      accent: Color(0xFF2A9D8F),
    ),
    _record(
      id: 'R-2402',
      species: '灰鹭',
      scientificName: 'Ardea cinerea',
      capturedAtTime: DateTime(2026, 4, 11, 8, 45),
      stationName: '东堤观察点',
      capturedAt: '2026-04-11 08:45',
      confidence: 0.94,
      temperature: 17.8,
      humidity: 68,
      uploadSummary: '设备自动上传 · 画面无遮挡，识别成功',
      accent: Color(0xFFE76F51),
    ),
    _record(
      id: 'R-2403',
      species: '夜鹭',
      scientificName: 'Nycticorax nycticorax',
      capturedAtTime: DateTime(2026, 4, 11, 8, 11),
      stationName: '北岸瞭望台',
      capturedAt: '2026-04-11 08:11',
      confidence: 0.91,
      temperature: 17.2,
      humidity: 71,
      uploadSummary: '设备自动上传 · 低光场景下完成识别',
      accent: Color(0xFF3D5A80),
    ),
    _record(
      id: 'R-2404',
      species: '苍鹭',
      scientificName: 'Ardea alba',
      capturedAtTime: DateTime(2026, 4, 10, 17, 58),
      stationName: '南湖湿地站',
      capturedAt: '2026-04-10 17:58',
      confidence: 0.89,
      temperature: 20.1,
      humidity: 59,
      uploadSummary: '设备自动上传 · 逆光条件下仍完成识别',
      accent: Color(0xFF8D99AE),
    ),
    _record(
      id: 'R-2405',
      species: '白鹭',
      scientificName: 'Egretta garzetta',
      capturedAtTime: DateTime(2026, 4, 10, 16, 40),
      stationName: '西侧林缘点',
      capturedAt: '2026-04-10 16:40',
      confidence: 0.95,
      temperature: 19.0,
      humidity: 60,
      uploadSummary: '设备自动上传 · 黄昏光照正常',
      accent: Color(0xFF2A9D8F),
    ),
    _record(
      id: 'R-2406',
      species: '白鹭',
      scientificName: 'Egretta garzetta',
      capturedAtTime: DateTime(2026, 4, 9, 18, 12),
      stationName: '南湖湿地站',
      capturedAt: '2026-04-09 18:12',
      confidence: 0.96,
      temperature: 18.6,
      humidity: 63,
      uploadSummary: '设备自动上传 · 傍晚时段稳定识别',
      accent: Color(0xFF2A9D8F),
    ),
    _record(
      id: 'R-2407',
      species: '灰鹭',
      scientificName: 'Ardea cinerea',
      capturedAtTime: DateTime(2026, 4, 9, 14, 50),
      stationName: '东堤观察点',
      capturedAt: '2026-04-09 14:50',
      confidence: 0.92,
      temperature: 19.2,
      humidity: 58,
      uploadSummary: '设备自动上传 · 白天中段画面清晰',
      accent: Color(0xFFE76F51),
    ),
    _record(
      id: 'R-2408',
      species: '夜鹭',
      scientificName: 'Nycticorax nycticorax',
      capturedAtTime: DateTime(2026, 4, 8, 7, 36),
      stationName: '北岸瞭望台',
      capturedAt: '2026-04-08 07:36',
      confidence: 0.90,
      temperature: 16.8,
      humidity: 74,
      uploadSummary: '设备自动上传 · 清晨低照度识别成功',
      accent: Color(0xFF3D5A80),
    ),
    _record(
      id: 'R-2409',
      species: '苍鹭',
      scientificName: 'Ardea alba',
      capturedAtTime: DateTime(2026, 4, 8, 11, 12),
      stationName: '西侧林缘点',
      capturedAt: '2026-04-08 11:12',
      confidence: 0.87,
      temperature: 17.5,
      humidity: 70,
      uploadSummary: '设备自动上传 · 树荫遮挡但仍完成识别',
      accent: Color(0xFF8D99AE),
    ),
    _record(
      id: 'R-2410',
      species: '白鹭',
      scientificName: 'Egretta garzetta',
      capturedAtTime: DateTime(2026, 4, 7, 6, 58),
      stationName: '南湖湿地站',
      capturedAt: '2026-04-07 06:58',
      confidence: 0.98,
      temperature: 15.9,
      humidity: 77,
      uploadSummary: '设备自动上传 · 早高峰识别稳定',
      accent: Color(0xFF2A9D8F),
    ),
    _record(
      id: 'R-2411',
      species: '白鹭',
      scientificName: 'Egretta garzetta',
      capturedAtTime: DateTime(2026, 4, 7, 9, 35),
      stationName: '东堤观察点',
      capturedAt: '2026-04-07 09:35',
      confidence: 0.93,
      temperature: 17.0,
      humidity: 69,
      uploadSummary: '设备自动上传 · 连续帧去重后保留结果',
      accent: Color(0xFF2A9D8F),
    ),
    _record(
      id: 'R-2412',
      species: '灰鹭',
      scientificName: 'Ardea cinerea',
      capturedAtTime: DateTime(2026, 4, 6, 17, 5),
      stationName: '北岸瞭望台',
      capturedAt: '2026-04-06 17:05',
      confidence: 0.88,
      temperature: 18.1,
      humidity: 62,
      uploadSummary: '设备自动上传 · 逆风环境下识别成功',
      accent: Color(0xFFE76F51),
    ),
    _record(
      id: 'R-2413',
      species: '夜鹭',
      scientificName: 'Nycticorax nycticorax',
      capturedAtTime: DateTime(2026, 4, 6, 15, 40),
      stationName: '西侧林缘点',
      capturedAt: '2026-04-06 15:40',
      confidence: 0.90,
      temperature: 18.8,
      humidity: 65,
      uploadSummary: '设备自动上传 · 树冠阴影场景识别完成',
      accent: Color(0xFF3D5A80),
    ),
    _record(
      id: 'R-2414',
      species: '苍鹭',
      scientificName: 'Ardea alba',
      capturedAtTime: DateTime(2026, 4, 5, 8, 21),
      stationName: '南湖湿地站',
      capturedAt: '2026-04-05 08:21',
      confidence: 0.91,
      temperature: 16.4,
      humidity: 72,
      uploadSummary: '设备自动上传 · 早间湿度较高',
      accent: Color(0xFF8D99AE),
    ),
    _record(
      id: 'R-2415',
      species: '白鹭',
      scientificName: 'Egretta garzetta',
      capturedAtTime: DateTime(2026, 4, 5, 19, 14),
      stationName: '东堤观察点',
      capturedAt: '2026-04-05 19:14',
      confidence: 0.94,
      temperature: 17.6,
      humidity: 67,
      uploadSummary: '设备自动上传 · 晚间归巢阶段识别成功',
      accent: Color(0xFF2A9D8F),
    ),
    _record(
      id: 'R-2416',
      species: '灰鹭',
      scientificName: 'Ardea cinerea',
      capturedAtTime: DateTime(2026, 4, 4, 10, 33),
      stationName: '北岸瞭望台',
      capturedAt: '2026-04-04 10:33',
      confidence: 0.89,
      temperature: 18.3,
      humidity: 61,
      uploadSummary: '设备自动上传 · 风速偏高但识别正常',
      accent: Color(0xFFE76F51),
    ),
    _record(
      id: 'R-2417',
      species: '夜鹭',
      scientificName: 'Nycticorax nycticorax',
      capturedAtTime: DateTime(2026, 4, 3, 13, 22),
      stationName: '南湖湿地站',
      capturedAt: '2026-04-03 13:22',
      confidence: 0.86,
      temperature: 19.1,
      humidity: 59,
      uploadSummary: '设备自动上传 · 午后样本保留',
      accent: Color(0xFF3D5A80),
    ),
    _record(
      id: 'R-2418',
      species: '苍鹭',
      scientificName: 'Ardea alba',
      capturedAtTime: DateTime(2026, 4, 3, 16, 47),
      stationName: '西侧林缘点',
      capturedAt: '2026-04-03 16:47',
      confidence: 0.90,
      temperature: 20.0,
      humidity: 57,
      uploadSummary: '设备自动上传 · 逆光场景自动补偿',
      accent: Color(0xFF8D99AE),
    ),
    _record(
      id: 'R-2419',
      species: '白鹭',
      scientificName: 'Egretta garzetta',
      capturedAtTime: DateTime(2026, 4, 2, 7, 9),
      stationName: '南湖湿地站',
      capturedAt: '2026-04-02 07:09',
      confidence: 0.92,
      temperature: 15.7,
      humidity: 76,
      uploadSummary: '设备自动上传 · 清晨薄雾下仍可识别',
      accent: Color(0xFF2A9D8F),
    ),
    _record(
      id: 'R-2420',
      species: '灰鹭',
      scientificName: 'Ardea cinerea',
      capturedAtTime: DateTime(2026, 4, 1, 18, 30),
      stationName: '东堤观察点',
      capturedAt: '2026-04-01 18:30',
      confidence: 0.88,
      temperature: 17.9,
      humidity: 64,
      uploadSummary: '设备自动上传 · 跨日统计样本',
      accent: Color(0xFFE76F51),
    ),
  ];

  BirdRecord _record({
    required String id,
    required String species,
    required String scientificName,
    required DateTime capturedAtTime,
    required String stationName,
    required String capturedAt,
    required double confidence,
    required double temperature,
    required int humidity,
    required String uploadSummary,
    required Color accent,
  }) {
    final deviceId =
        _stationDeviceIds[stationName] ??
        '8c0a2c1d-0b1f-4e56-b3e2-11a5f0b6b099';
    return BirdRecord(
      id: id,
      species: species,
      scientificName: scientificName,
      capturedAtTime: capturedAtTime,
      stationName: stationName,
      capturedAt: capturedAt,
      confidence: confidence,
      temperature: temperature,
      humidity: humidity,
      uploadSummary: uploadSummary,
      speciesIntro: _speciesIntro(species),
      accent: accent,
      recordId: id,
      deviceId: deviceId,
      deviceName: stationName,
      speciesEntityId: switch (species) {
        '白鹭' => 'd5d1cb2d-55b3-4b1d-8b31-7ff8f8d7a001',
        '灰鹭' => 'd5d1cb2d-55b3-4b1d-8b31-7ff8f8d7a002',
        '夜鹭' => 'd5d1cb2d-55b3-4b1d-8b31-7ff8f8d7a003',
        '苍鹭' => 'd5d1cb2d-55b3-4b1d-8b31-7ff8f8d7a004',
        _ => null,
      },
      capturedAtMs: capturedAtTime.millisecondsSinceEpoch,
      temperatureC: temperature,
      humidityPct: humidity,
      mediaRefs: const [],
      processingSource: 'edge',
      modelVersion: 'demo-v1',
      recordStatus: 'published',
      summaryText: uploadSummary,
    );
  }

  String _speciesIntro(String species) {
    return switch (species) {
      '白鹭' =>
        '白鹭（Egretta garzetta），又称小白鹭，是鹭科中的一种小型鹭。它是一种白色的鸟，具有细长的黑色喙、长黑腿，常见于湿地、河口与浅水岸边，擅长缓慢涉水觅食。',
      '灰鹭' =>
        '灰鹭（Ardea cinerea）体型修长，羽色以灰白为主，飞行时颈部会收缩成 S 形。它常活动于湖泊、沼泽和水渠附近，凭借长喙快速捕捉鱼类、两栖动物和小型无脊椎动物。',
      '夜鹭' =>
        '夜鹭（Nycticorax nycticorax）是一种中型鹭类，常在黄昏或夜间活动。它身体敦实，颈背具黑色羽毛，白色腹部与红色眼睛是其显著特征，喜欢在湖岸、池塘和湿地边缘觅食。',
      '苍鹭' =>
        '苍鹭（Ardea alba）体态高挑，羽色纯白，颈部较长，通常独立或小群活动。它偏好开阔水域和湿地环境，常以静候方式捕食鱼虾和小型水生生物。',
      _ => '该物种的简介暂未配置。',
    };
  }

  @override
  Future<List<RecordStationOption>> fetchStationOptions() async {
    return List<RecordStationOption>.unmodifiable(
      _stations
          .map(
            (stationName) => RecordStationOption(
              deviceId: _stationDeviceIds[stationName] ?? '',
              deviceName: stationName,
            ),
          )
          .toList(),
    );
  }

  @override
  Future<List<BirdRecord>> fetchRecords({
    DateTimeRange? dateRange,
    String? stationId,
  }) async {
    final filtered = records.where((record) {
      final stationMatch = stationId == null || stationId.isEmpty
          ? true
          : record.deviceIdValue == stationId;

      final dateMatch = dateRange == null
          ? true
          : (() {
              final start = DateUtils.dateOnly(dateRange.start);
              final endExclusive = DateUtils.dateOnly(
                dateRange.end,
              ).add(const Duration(days: 1));
              return !record.capturedAtTime.isBefore(start) &&
                  record.capturedAtTime.isBefore(endExclusive);
            })();

      return stationMatch && dateMatch;
    }).toList()
      ..sort((left, right) => right.capturedAtTime.compareTo(left.capturedAtTime));

    return filtered;
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

  @override
  Future<RecordCursorPage> fetchRecordsByCursor({
    DateTimeRange? dateRange,
    String? stationId,
    String? cursor,
    int limit = 20,
  }) async {
    final filtered = await fetchRecords(dateRange: dateRange, stationId: stationId);
    final pageLimit = limit <= 0 ? 20 : limit;
    final start = _decodeCursor(cursor).clamp(0, filtered.length);
    final end = (start + pageLimit).clamp(0, filtered.length);
    final items = filtered.sublist(start, end);
    final hasMore = end < filtered.length;

    return RecordCursorPage(
      items: items,
      nextCursor: hasMore ? '$end' : null,
      hasMore: hasMore,
    );
  }

  @override
  List<TrendPoint> get trends => const [
    TrendPoint(label: '周一', value: 42),
    TrendPoint(label: '周二', value: 54),
    TrendPoint(label: '周三', value: 36),
    TrendPoint(label: '周四', value: 61),
    TrendPoint(label: '周五', value: 48),
    TrendPoint(label: '周六', value: 72),
    TrendPoint(label: '周日', value: 66),
  ];

  @override
  List<SpeciesShare> get speciesShares => const [
    SpeciesShare(label: '白鹭', value: 36, color: Color(0xFF2A9D8F)),
    SpeciesShare(label: '灰鹭', value: 24, color: Color(0xFFE76F51)),
    SpeciesShare(label: '夜鹭', value: 18, color: Color(0xFF3D5A80)),
    SpeciesShare(label: '苍鹭', value: 12, color: Color(0xFF8D99AE)),
  ];
}
