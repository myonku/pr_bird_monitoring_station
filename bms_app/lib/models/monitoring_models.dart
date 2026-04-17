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

enum AppMode { development, noAuth }

extension AppModeLabel on AppMode {
  String get label => switch (this) {
    AppMode.development => 'development',
    AppMode.noAuth => 'no-auth',
  };

  String get displayName => switch (this) {
    AppMode.development => 'Development',
    AppMode.noAuth => 'No-Auth',
  };
}

class DashboardSnapshot {
  const DashboardSnapshot({
    required this.todayRecognition,
    required this.todayNewRecords,
    required this.onlineStations,
    required this.onlineDevices,
    required this.lastUploadTime,
    required this.highlightedBird,
    this.lastUploadAtMs,
    this.serverTimeMs,
  });

  final int todayRecognition;
  final int todayNewRecords;
  final int onlineStations;
  final int onlineDevices;
  final String lastUploadTime;
  final String highlightedBird;
  final int? lastUploadAtMs;
  final int? serverTimeMs;

  int get todayRecognitionCount => todayRecognition;
  int get todayNewRecordCount => todayNewRecords;
  int get onlineStationCount => onlineStations;
  int get onlineDeviceCount => onlineDevices;

  String get lastUploadAtLabel => lastUploadTime.isNotEmpty
      ? lastUploadTime
      : lastUploadAtMs == null
      ? ''
      : _formatDateTimeMs(lastUploadAtMs!);
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
    required this.station,
    required this.phone,
    required this.avatarSeed,
    this.userId,
    this.username,
    this.displayName,
    this.deviceName,
    this.email,
  });

  final String name;
  final String role;
  final String station;
  final String phone;
  final int avatarSeed;
  final String? userId;
  final String? username;
  final String? displayName;
  final String? deviceName;
  final String? email;

  String get displayNameValue => displayName ?? name;
  String get deviceNameValue => deviceName ?? station;
}
