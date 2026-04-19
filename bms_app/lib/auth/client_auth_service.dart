import 'package:bms_app/models/auth_models.dart';
import 'package:bms_app/auth/auth_service.dart';
import 'package:bms_app/credential_manager/credential_manager.dart';
import 'package:bms_app/transport/transport_client.dart';
import 'package:bms_app/models/api_models.dart';
import 'package:bms_app/models/common.dart';
import 'package:bms_app/models/transport/client_resp_dto.dart';
import 'package:bms_app/models/transport/client_req_dto.dart';


class ClientAuthService implements AuthService {
  ClientAuthService({
    required MonitoringClient client,
    required MonitoringCredentialManager credentials,
    required AppUser defaultUser,
  })  : _client = client,
        _credentials = credentials,
        _defaultUser = defaultUser;

  final MonitoringClient _client;
  final MonitoringCredentialManager _credentials;
  final AppUser _defaultUser;

  @override
  AppUser get defaultUser => _defaultUser;

  @override
  Future<AppUser?> fetchUserProfile(String identifier) async {
    final normalized = identifier.trim();
    if (normalized.isEmpty) {
      return _defaultUser;
    }

    if (_credentials.mode == AppMode.noAuth) {
      try {
        final response = await _client.fetchUserProfile(
          ClientUserProfileRequest(identifier: normalized),
          options: const ClientRequestOptions(headers: <String, String>{}),
        );
        return response == null ? _defaultUser : _toAppUser(response);
      } catch (_) {
        return _defaultUser;
      }
    }

    final headers = await _credentials.buildAuthHeaders(
      refreshSession: _refreshSession,
    );
    final response = await _client.fetchUserProfile(
      ClientUserProfileRequest(identifier: normalized),
      options: ClientRequestOptions(headers: headers),
    );
    return response == null ? _defaultUser : _toAppUser(response);
  }

  @override
  Future<AuthSession> refreshSession(AuthSession session) async {
    final refreshedCredentials = await _client.refreshSession(
      ClientRefreshSessionRequest(
        sessionId: session.credentials.sessionId?.trim() ?? '',
        refreshToken: session.credentials.refreshToken?.trim() ?? '',
        tokenId: session.credentials.tokenId?.trim() ?? '',
        tokenFamilyId: session.credentials.tokenFamilyId?.trim() ?? '',
        principalId: session.credentials.principalId?.trim() ?? '',
        scopes: session.credentials.scopes,
      ),
    );

    final refreshed = _toAuthSession(
      loginIdentifier: session.loginIdentifier,
      mode: session.mode,
      credentials: refreshedCredentials,
      signedInAt: session.signedInAt,
    );
    await _credentials.storeSession(refreshed);
    return refreshed;
  }

  @override
  Future<RegistrationResult> registerUser({
    required String username,
    String email = '',
    String phone = '',
    required String password,
  }) async {
    final result = await _client.registerUser(
      ClientRegisterRequest(
        username: username,
        email: email,
        phone: phone,
        password: password,
      ),
    );

    return RegistrationResult(
      ok: result.ok,
      errorCode: result.errorCode,
      message: result.message,
    );
  }

  @override
  Future<AuthSession> signIn({
    required String identifier,
    required String password,
    required AppMode mode,
  }) async {
    final now = DateTime.now();
    if (mode == AppMode.noAuth) {
      final session = AuthSession(
        loginIdentifier: identifier.trim(),
        credentials: const AuthCredentials(),
        mode: mode,
        signedInAt: now,
      );
      await _credentials.setMode(mode);
      await _credentials.storeSession(session);
      return session;
    }

    await _credentials.setMode(mode);
    final credentials = await _client.signIn(
      ClientSignInRequest(identifier: identifier, password: password),
    );

    final session = _toAuthSession(
      loginIdentifier: identifier.trim(),
      mode: mode,
      credentials: credentials,
      signedInAt: now,
    );
    if (!session.credentials.hasAccessToken ||
        !session.credentials.hasRefreshToken ||
        !session.credentials.toAuthHeaders().isReadyForHttp) {
      throw StateError('登录信息已失效，请重新登录');
    }

    await _credentials.storeSession(session);
    return session;
  }

  @override
  Future<void> signOut({AuthSession? session}) async {
    await _credentials.clearSession();
  }

  Future<AuthSession> _refreshSession(AuthSession session) {
    return refreshSession(session);
  }

  AppUser _toAppUser(ClientUserProfileResponse response) {
    return AppUser(
      userId: response.userId,
      username: response.username,
      displayName: response.displayName,
      name: response.name,
      role: response.role,
      email: response.email,
      phone: response.phone,
      avatarSeed: response.avatarSeed,
    );
  }

  AuthSession _toAuthSession({
    required String loginIdentifier,
    required AppMode mode,
    required ClientAuthCredentialsResponse credentials,
    required DateTime signedInAt,
  }) {
    return AuthSession(
      loginIdentifier: loginIdentifier,
      credentials: AuthCredentials(
        accessToken: credentials.accessToken,
        refreshToken: credentials.refreshToken,
        downstreamToken: credentials.downstreamToken,
        tokenType: credentials.tokenType,
        sessionId: credentials.sessionId,
        tokenId: credentials.tokenId,
        principalId: credentials.principalId,
        tokenFamilyId: credentials.tokenFamilyId,
        scopes: credentials.scopes,
        issuedAtMs: credentials.issuedAtMs,
        accessExpiresAtMs: credentials.accessExpiresAtMs,
        refreshExpiresAtMs: credentials.refreshExpiresAtMs,
        persisted: credentials.persisted,
      ),
      mode: mode,
      signedInAt: signedInAt,
    );
  }
}