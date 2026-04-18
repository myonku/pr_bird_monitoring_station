import 'package:bms_app/data_source/monitoring_repository.dart';
import 'package:bms_app/models/monitoring_models.dart';

abstract class HomeDataSource {
  Future<DashboardSnapshot> fetchDashboardSnapshot();
}

class RepositoryHomeDataSource implements HomeDataSource {
  const RepositoryHomeDataSource(this.repository);

  final MonitoringRepository repository;

  @override
  Future<DashboardSnapshot> fetchDashboardSnapshot() =>
      repository.fetchDashboardSnapshot();
}
