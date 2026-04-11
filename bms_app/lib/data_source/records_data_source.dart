import 'package:flutter/material.dart';

import 'package:bms_app/data_source/monitoring_repository.dart';
import 'package:bms_app/models/monitoring_models.dart';

abstract class RecordsDataSource {
  int get totalRecordCount;

  Future<List<String>> fetchStationOptions();

  Future<List<BirdRecord>> fetchRecords({
    DateTimeRange? dateRange,
    String? stationName,
  });
}

class RepositoryRecordsDataSource implements RecordsDataSource {
  const RepositoryRecordsDataSource(this.repository);

  final MonitoringRepository repository;

  @override
  int get totalRecordCount => repository.records.length;

  @override
  Future<List<String>> fetchStationOptions() =>
      repository.fetchStationOptions();

  @override
  Future<List<BirdRecord>> fetchRecords({
    DateTimeRange? dateRange,
    String? stationName,
  }) {
    return repository.fetchRecords(
      dateRange: dateRange,
      stationName: stationName,
    );
  }
}
