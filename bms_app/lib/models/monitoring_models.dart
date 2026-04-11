import 'package:flutter/material.dart';

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
  });

  final int todayRecognition;
  final int todayNewRecords;
  final int onlineStations;
  final int onlineDevices;
  final String lastUploadTime;
  final String highlightedBird;
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
}

class TrendPoint {
  const TrendPoint({required this.label, required this.value});

  final String label;
  final int value;
}

class SpeciesShare {
  const SpeciesShare({
    required this.label,
    required this.value,
    required this.color,
  });

  final String label;
  final int value;
  final Color color;
}

class AppUser {
  const AppUser({
    required this.name,
    required this.role,
    required this.station,
    required this.phone,
    required this.avatarSeed,
  });

  final String name;
  final String role;
  final String station;
  final String phone;
  final int avatarSeed;
}
