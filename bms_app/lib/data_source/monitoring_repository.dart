import 'package:flutter/material.dart';

import 'package:bms_app/models/monitoring_models.dart';

abstract class MonitoringRepository {
  DashboardSnapshot get dashboard;

  AppUser get defaultUser;

  AppUser userForName(String name);

  List<BirdRecord> get records;

  Future<List<String>> fetchStationOptions();

  Future<List<BirdRecord>> fetchRecords({
    DateTimeRange? dateRange,
    String? stationName,
  });

  List<TrendPoint> get trends;

  List<SpeciesShare> get speciesShares;
}
