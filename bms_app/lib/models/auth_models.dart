import 'package:bms_app/models/common.dart';

class AuthHeaders {
  const AuthHeaders({
    required this.authorization,
    required this.sessionId,
    required this.tokenId,
    required this.tokenType,
    required this.principalId,
    this.scopes = const [],
  });

  const AuthHeaders.empty()
    : authorization = '',
      sessionId = '',
      tokenId = '',
      tokenType = '',
      principalId = '',
      scopes = const [];

  factory AuthHeaders.fromCredentials(AuthCredentials credentials) {
    final accessToken = credentials.accessToken?.trim() ?? '';
    return AuthHeaders(
      authorization: accessToken.isEmpty ? '' : 'Bearer $accessToken',
      sessionId: credentials.sessionId?.trim() ?? '',
      tokenId: credentials.tokenId?.trim() ?? '',
      tokenType: credentials.tokenType.trim(),
      principalId: credentials.principalId?.trim() ?? '',
      scopes: credentials.scopes,
    );
  }

  final String authorization;
  final String sessionId;
  final String tokenId;
  final String tokenType;
  final String principalId;
  final List<String> scopes;

  bool get isEmpty =>
      authorization.trim().isEmpty &&
      sessionId.trim().isEmpty &&
      tokenId.trim().isEmpty &&
      tokenType.trim().isEmpty &&
      principalId.trim().isEmpty &&
      scopes.isEmpty;

  bool get isReadyForHttp =>
      authorization.trim().isNotEmpty &&
      sessionId.trim().isNotEmpty &&
      tokenId.trim().isNotEmpty &&
      tokenType.trim().isNotEmpty &&
      principalId.trim().isNotEmpty;

  Map<String, String> toHttpHeaders() {
    final headers = <String, String>{};

    final authorizationValue = authorization.trim();
    if (authorizationValue.isNotEmpty) {
      headers['Authorization'] = authorizationValue;
    }

    final sessionValue = sessionId.trim();
    if (sessionValue.isNotEmpty) {
      headers['x-downstream-session-id'] = sessionValue;
    }

    final tokenIdValue = tokenId.trim();
    if (tokenIdValue.isNotEmpty) {
      headers['x-downstream-token-id'] = tokenIdValue;
    }

    final tokenTypeValue = tokenType.trim();
    if (tokenTypeValue.isNotEmpty) {
      headers['x-token-type'] = tokenTypeValue;
    }

    final principalValue = principalId.trim();
    if (principalValue.isNotEmpty) {
      headers['x-downstream-principal'] = principalValue;
    }

    final normalizedScopes = scopes
        .map((scope) => scope.trim())
        .where((scope) => scope.isNotEmpty)
        .toList(growable: false);
    if (normalizedScopes.isNotEmpty) {
      headers['x-scopes'] = normalizedScopes.join(',');
    }

    return headers;
  }
}

class AuthCredentials {
  const AuthCredentials({
    this.accessToken,
    this.refreshToken,
    this.downstreamToken,
    this.tokenType = 'access',
    this.sessionId,
    this.tokenId,
    this.principalId,
    this.tokenFamilyId,
    this.scopes = const [],
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
  final String? tokenId;
  final String? principalId;
  final String? tokenFamilyId;
  final List<String> scopes;
  final int? issuedAtMs;
  final int? accessExpiresAtMs;
  final int? refreshExpiresAtMs;
  final bool persisted;

  bool get isEmpty =>
      accessToken == null && refreshToken == null && downstreamToken == null;

  bool get hasAccessToken => _hasValue(accessToken);
  bool get hasRefreshToken => _hasValue(refreshToken);
  bool get hasDownstreamToken => _hasValue(downstreamToken);

  bool isAccessTokenUsable(DateTime now, {Duration skew = Duration.zero}) {
    if (!hasAccessToken) {
      return false;
    }
    final expiresAtMs = accessExpiresAtMs;
    if (expiresAtMs == null) {
      return false;
    }
    final safeSkew = skew.isNegative ? Duration.zero : skew;
    return now.millisecondsSinceEpoch + safeSkew.inMilliseconds < expiresAtMs;
  }

  bool isRefreshTokenUsable(DateTime now, {Duration skew = Duration.zero}) {
    if (!hasRefreshToken) {
      return false;
    }
    final expiresAtMs = refreshExpiresAtMs;
    if (expiresAtMs == null) {
      return false;
    }
    final safeSkew = skew.isNegative ? Duration.zero : skew;
    return now.millisecondsSinceEpoch + safeSkew.inMilliseconds < expiresAtMs;
  }

  AuthHeaders toAuthHeaders() => AuthHeaders.fromCredentials(this);

  AuthCredentials copyWith({
    String? accessToken,
    String? refreshToken,
    String? downstreamToken,
    String? tokenType,
    String? sessionId,
    String? tokenId,
    String? principalId,
    String? tokenFamilyId,
    List<String>? scopes,
    int? issuedAtMs,
    int? accessExpiresAtMs,
    int? refreshExpiresAtMs,
    bool? persisted,
  }) {
    return AuthCredentials(
      accessToken: accessToken ?? this.accessToken,
      refreshToken: refreshToken ?? this.refreshToken,
      downstreamToken: downstreamToken ?? this.downstreamToken,
      tokenType: tokenType ?? this.tokenType,
      sessionId: sessionId ?? this.sessionId,
      tokenId: tokenId ?? this.tokenId,
      principalId: principalId ?? this.principalId,
      tokenFamilyId: tokenFamilyId ?? this.tokenFamilyId,
      scopes: scopes ?? this.scopes,
      issuedAtMs: issuedAtMs ?? this.issuedAtMs,
      accessExpiresAtMs: accessExpiresAtMs ?? this.accessExpiresAtMs,
      refreshExpiresAtMs: refreshExpiresAtMs ?? this.refreshExpiresAtMs,
      persisted: persisted ?? this.persisted,
    );
  }

  Map<String, String> buildAuthHeaders() {
    return toAuthHeaders().toHttpHeaders();
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

  AuthSession copyWith({
    String? loginIdentifier,
    AuthCredentials? credentials,
    AppMode? mode,
    DateTime? signedInAt,
  }) {
    return AuthSession(
      loginIdentifier: loginIdentifier ?? this.loginIdentifier,
      credentials: credentials ?? this.credentials,
      mode: mode ?? this.mode,
      signedInAt: signedInAt ?? this.signedInAt,
    );
  }
}
