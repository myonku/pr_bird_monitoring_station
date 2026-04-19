import 'package:flutter/material.dart';

String _formatDateTimeMs(int millisecondsSinceEpoch) {
  final dateTime = DateTime.fromMillisecondsSinceEpoch(
    millisecondsSinceEpoch,
  ).toLocal();
  final year = dateTime.year.toString().padLeft(4, '0');
  final month = dateTime.month.toString().padLeft(2, '0');
  final day = dateTime.day.toString().padLeft(2, '0');
  final hour = dateTime.hour.toString().padLeft(2, '0');
  final minute = dateTime.minute.toString().padLeft(2, '0');
  return '$year-$month-$day $hour:$minute';
}

enum MonitoringDataSource { mockClient, httpClient }
enum AppMode { development, noAuth }

extension AppModeLabel on AppMode {
  String get label => switch (this) {
    AppMode.development => 'development',
    AppMode.noAuth => 'no-auth',
  };

  String get displayName => switch (this) {
    AppMode.development => '测试模式',
    AppMode.noAuth => '无认证模式',
  };

  Color get seedColor => switch (this) {
    AppMode.development => const Color(0xFF0B7A75),
    AppMode.noAuth => const Color(0xFFC97C1D),
  };

  List<Color> get bannerColors => switch (this) {
    AppMode.development => const [Color(0xFF0B7A75), Color(0xFF125D98)],
    AppMode.noAuth => const [Color(0xFFC97C1D), Color(0xFFE09F3E)],
  };
}

class UploadStationSummary {
  const UploadStationSummary({
    required this.deviceId,
    required this.deviceName,
    required this.uploadCount,
  });

  final String deviceId;
  final String deviceName;
  final int uploadCount;
}

class LatestUploadSummary {
  const LatestUploadSummary({
    required this.deviceId,
    required this.deviceName,
    required this.uploadedAtLabel,
    this.uploadedAtMs,
  });

  final String deviceId;
  final String deviceName;
  final String uploadedAtLabel;
  final int? uploadedAtMs;

  String get uploadedAtValue => uploadedAtLabel.isNotEmpty
      ? uploadedAtLabel
      : uploadedAtMs == null
      ? ''
      : _formatDateTimeMs(uploadedAtMs!);
}

class RecordStationOption {
  const RecordStationOption({
    required this.deviceId,
    required this.deviceName,
  });

  final String deviceId;
  final String deviceName;

  bool get isAll => deviceId.isEmpty;
}

class RecordCursorPage {
  const RecordCursorPage({
    required this.items,
    required this.nextCursor,
    required this.hasMore,
  });

  final List<BirdRecord> items;
  final String? nextCursor;
  final bool hasMore;
}

class DashboardSnapshot {
  const DashboardSnapshot({
    required this.todayRecognitionCount,
    required this.todayUploadCount,
    required this.onlineStationCount,
    required this.activeStationCount,
    required this.topUploadStation,
    required this.latestUpload,
    required this.recentRecords,
  });

  final int todayRecognitionCount;
  final int todayUploadCount;
  final int onlineStationCount;
  final int activeStationCount;
  final UploadStationSummary topUploadStation;
  final LatestUploadSummary latestUpload;
  final List<BirdRecord> recentRecords;

  int get todayRecognition => todayRecognitionCount;
  int get todayNewRecords => todayUploadCount;
  int get onlineStations => onlineStationCount;
  int get onlineDevices => activeStationCount;
  String get lastUploadTime => latestUpload.uploadedAtValue;
  String get highlightedBird => topUploadStation.deviceName;
}

class BirdRecord {
  const BirdRecord({
    required this.id,
    required this.species,
    required this.scientificName,
    required this.capturedAtTime,
    required this.stationName,
    required this.capturedAt,
    required this.confidence,
    required this.temperature,
    required this.humidity,
    required this.uploadSummary,
    required this.speciesIntro,
    required this.accent,
    this.recordId,
    this.deviceId,
    this.deviceName,
    this.speciesEntityId,
    this.capturedAtMs,
    this.temperatureC,
    this.humidityPct,
    this.mediaRefs = const [],
    this.processingSource = 'edge',
    this.modelVersion = '',
    this.recordStatus = 'received',
    this.summaryText,
  });

  final String id;
  final String species;
  final String scientificName;
  final DateTime capturedAtTime;
  final String stationName;
  final String capturedAt;
  final double confidence;
  final double temperature;
  final int humidity;
  final String uploadSummary;
  final String speciesIntro;
  final Color accent;
  final String? recordId;
  final String? deviceId;
  final String? deviceName;
  final String? speciesEntityId;
  final int? capturedAtMs;
  final double? temperatureC;
  final int? humidityPct;
  final List<String> mediaRefs;
  final String processingSource;
  final String modelVersion;
  final String recordStatus;
  final String? summaryText;

  String get recordIdValue => recordId ?? id;
  String get deviceIdValue => deviceId ?? '';
  String get deviceNameValue => deviceName ?? stationName;
  String get speciesNameValue => species;
  String get summaryTextValue => summaryText ?? uploadSummary;
  int get capturedAtMsValue =>
      capturedAtMs ?? capturedAtTime.millisecondsSinceEpoch;
  double get temperatureCValue => temperatureC ?? temperature;
  int get humidityPctValue => humidityPct ?? humidity;
}

class TrendPoint {
  const TrendPoint({required this.label, required this.value, this.dateMs});

  final String label;
  final int value;
  final int? dateMs;
}

class SpeciesShare {
  const SpeciesShare({
    required this.label,
    required this.value,
    required this.color,
    this.speciesEntityId,
  });

  final String label;
  final int value;
  final Color color;
  final String? speciesEntityId;
}

class AppUser {
  const AppUser({
    required this.name,
    required this.role,
    required this.phone,
    required this.avatarSeed,
    this.userId,
    this.username,
    this.displayName,
    this.email,
  });

  final String name;
  final String role;
  final String phone;
  final int avatarSeed;
  final String? userId;
  final String? username;
  final String? displayName;
  final String? email;

  String get displayNameValue => displayName ?? name;
}

class RegistrationErrorCode {
  static const String usernameExists = 'username_exists';
  static const String emailExists = 'email_exists';
  static const String phoneExists = 'phone_exists';
  static const String invalidData = 'invalid_data';
  static const String dataError = 'data_error';
  static const String unknownError = 'unknown_error';
}

class RegistrationResult {
  const RegistrationResult({
    required this.ok,
    this.errorCode = '',
    this.message = '',
  });

  final bool ok;
  final String errorCode;
  final String message;
}
