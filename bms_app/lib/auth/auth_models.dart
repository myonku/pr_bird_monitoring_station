import 'package:bms_app/models/monitoring_models.dart';

class AuthCredentials {
  const AuthCredentials({
    this.accessToken,
    this.refreshToken,
    this.persisted = false,
    this.issuedAt,
  });

  final String? accessToken;
  final String? refreshToken;
  final bool persisted;
  final DateTime? issuedAt;

  bool get isEmpty => accessToken == null && refreshToken == null;

  Map<String, String> buildAuthHeaders() {
    if (isEmpty) {
      return const {};
    }

    return {
      'authorization': 'Bearer $accessToken',
      'x-refresh-token': ?refreshToken,
    };
  }
}

class AuthSession {
  const AuthSession({
    required this.user,
    required this.credentials,
    required this.mode,
    required this.signedInAt,
  });

  final AppUser user;
  final AuthCredentials credentials;
  final AppMode mode;
  final DateTime signedInAt;

  bool get hasCredentials => !credentials.isEmpty;
}
