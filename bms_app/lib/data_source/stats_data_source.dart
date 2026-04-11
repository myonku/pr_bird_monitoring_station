import 'package:bms_app/data_source/monitoring_repository.dart';
import 'package:bms_app/models/monitoring_models.dart';

abstract class StatsDataSource {
  List<TrendPoint> get weeklyTrend;
}

class RepositoryStatsDataSource implements StatsDataSource {
  const RepositoryStatsDataSource(this.repository);

  final MonitoringRepository repository;

  @override
  List<TrendPoint> get weeklyTrend => repository.trends;
}
