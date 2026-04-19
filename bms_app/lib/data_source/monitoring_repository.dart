import 'package:flutter/material.dart';

import 'package:bms_app/models/common.dart';

/// Client business repository contract.
///
/// Implementations should receive auth headers from the transport layer in
/// authenticated mode; registration and no-auth mode may omit them.
abstract class MonitoringRepository {
  int countTodayMonitoringRecords();

  int countTodayUploadRecords();

  int countOnlineStations();

  UploadStationSummary getTodayTopUploadStation();

  LatestUploadSummary getLatestUploadSummary();

  Future<DashboardSnapshot> fetchDashboardSnapshot();

  AppUser get defaultUser;

  Future<AppUser?> fetchUserProfile(String identifier);

  Future<RegistrationResult> registerUser({
    required String username,
    String email = '',
    String phone = '',
    required String password,
  });

  List<BirdRecord> get records;

  Future<List<RecordStationOption>> fetchStationOptions();

  Future<RecordCursorPage> fetchRecordsByCursor({
    DateTimeRange? dateRange,
    String? stationId,
    String? cursor,
    int limit = 20,
  });

  Future<List<TrendPoint>> fetchWeeklyTrend({
    int days = 7,
    String? stationId,
  });

  Future<List<BirdRecord>> fetchRecords({
    DateTimeRange? dateRange,
    String? stationId,
  });

  List<TrendPoint> get trends;

  List<SpeciesShare> get speciesShares;
}
