import 'package:bms_app/models/common.dart';
import 'package:bms_app/transport/http_client.dart';
import 'package:bms_app/transport/mock_client.dart';
import 'package:bms_app/transport/transport_client.dart';

MonitoringClient buildMonitoringClient(MonitoringDataSource dataSource, String serverBaseUrl) {
  return switch (dataSource) {
    MonitoringDataSource.httpClient => HttpMonitoringClient(
      baseUrl: serverBaseUrl,
    ),
    MonitoringDataSource.mockClient => MockMonitoringClient(),
  };
}
