import 'package:bms_app/data_source/monitoring_repository.dart';
import 'package:bms_app/models/monitoring_models.dart';

abstract class HomeDataSource {
  DashboardSnapshot get dashboard;

  List<BirdRecord> get recentRecords;

  MapEntry<String, int> get peakStationEntry;

  int get totalRecordCount;
}

class RepositoryHomeDataSource implements HomeDataSource {
  const RepositoryHomeDataSource(this.repository);

  final MonitoringRepository repository;

  @override
  DashboardSnapshot get dashboard => repository.dashboard;

  @override
  List<BirdRecord> get recentRecords => repository.records.take(3).toList();

  @override
  MapEntry<String, int> get peakStationEntry {
    final recordCountsByStation = <String, int>{};
    for (final record in repository.records) {
      recordCountsByStation[record.stationName] =
          (recordCountsByStation[record.stationName] ?? 0) + 1;
    }

    if (recordCountsByStation.isEmpty) {
      return const MapEntry('暂无数据', 0);
    }

    return recordCountsByStation.entries.reduce(
      (current, next) => current.value >= next.value ? current : next,
    );
  }

  @override
  int get totalRecordCount => repository.records.length;
}
