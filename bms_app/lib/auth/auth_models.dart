import 'package:bms_app/models/monitoring_models.dart';

class AuthCredentials {
  const AuthCredentials({
    this.accessToken,
    this.refreshToken,
    this.downstreamToken,
    this.tokenType = 'Bearer',
    this.sessionId,
    this.issuedAtMs,
    this.accessExpiresAtMs,
    this.refreshExpiresAtMs,
    this.persisted = false,
  });

  final String? accessToken;
  final String? refreshToken;
  final String? downstreamToken;
  final String tokenType;
  final String? sessionId;
  final int? issuedAtMs;
  final int? accessExpiresAtMs;
  final int? refreshExpiresAtMs;
  final bool persisted;

  bool get isEmpty =>
      accessToken == null && refreshToken == null && downstreamToken == null;

  bool get hasAccessToken => _hasValue(accessToken);
  bool get hasRefreshToken => _hasValue(refreshToken);
  bool get hasDownstreamToken => _hasValue(downstreamToken);

  Map<String, String> buildAuthHeaders() {
    if (isEmpty) {
      return const {};
    }

    final headers = <String, String>{};
    if (hasAccessToken) {
      headers['Authorization'] =
          '${tokenType.trim().isEmpty ? 'Bearer' : tokenType.trim()} ${accessToken!.trim()}';
    }
    if (hasRefreshToken) {
      headers['X-Refresh-Token'] = refreshToken!.trim();
    }
    if (_hasValue(sessionId)) {
      headers['X-Session-Id'] = sessionId!.trim();
    }
    if (hasDownstreamToken) {
      headers['X-Downstream-Token'] = downstreamToken!.trim();
    }
    return headers;
  }

  static bool _hasValue(String? value) =>
      value != null && value.trim().isNotEmpty;
}

class AuthSession {
  const AuthSession({
    required this.loginIdentifier,
    required this.credentials,
    required this.mode,
    required this.signedInAt,
  });

  final String loginIdentifier;
  final AuthCredentials credentials;
  final AppMode mode;
  final DateTime signedInAt;

  bool get hasCredentials => !credentials.isEmpty;
}
