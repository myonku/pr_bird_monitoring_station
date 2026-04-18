import 'package:flutter/material.dart';

import 'package:bms_app/data_source/monitoring_repository.dart';
import 'package:bms_app/models/monitoring_models.dart';

abstract class RecordsDataSource {
  Future<List<RecordStationOption>> fetchStationOptions();

  Future<RecordCursorPage> fetchRecordsByCursor({
    DateTimeRange? dateRange,
    String? stationId,
    String? cursor,
    int limit = 20,
  });

  Future<List<BirdRecord>> fetchRecords({
    DateTimeRange? dateRange,
    String? stationId,
  });
}

class RepositoryRecordsDataSource implements RecordsDataSource {
  const RepositoryRecordsDataSource(this.repository);

  final MonitoringRepository repository;

  @override
  Future<List<RecordStationOption>> fetchStationOptions() =>
      repository.fetchStationOptions();

  @override
  Future<RecordCursorPage> fetchRecordsByCursor({
    DateTimeRange? dateRange,
    String? stationId,
    String? cursor,
    int limit = 20,
  }) {
    return repository.fetchRecordsByCursor(
      dateRange: dateRange,
      stationId: stationId,
      cursor: cursor,
      limit: limit,
    );
  }

  @override
  Future<List<BirdRecord>> fetchRecords({
    DateTimeRange? dateRange,
    String? stationId,
  }) async {
    final allRecords = <BirdRecord>[];
    String? cursor;

    while (true) {
      final page = await fetchRecordsByCursor(
        dateRange: dateRange,
        stationId: stationId,
        cursor: cursor,
        limit: 50,
      );
      allRecords.addAll(page.items);

      if (!page.hasMore || page.nextCursor == null || page.nextCursor!.isEmpty) {
        break;
      }
      cursor = page.nextCursor;
    }

    return allRecords;
  }
}
