import 'package:bms_app/models/auth_models.dart';
import 'package:bms_app/storage/storage.dart';
import 'package:bms_app/models/common.dart';
import 'package:bms_app/storage/auth_stores.dart';

class MonitoringCredentialManager {
  MonitoringCredentialManager({
    AppMode initialMode = AppMode.development,
    AuthSessionStore? sessionStore,
  }) : this._internal(
         initialMode: initialMode,
         persistentSessionStore: sessionStore ?? MemoryAuthSessionStore(),
       );

  MonitoringCredentialManager._internal({
    required AppMode initialMode,
    required AuthSessionStore persistentSessionStore,
  })  : _mode = initialMode,
        _persistentSessionStore = persistentSessionStore,
        _sessionStore = initialMode == AppMode.noAuth
            ? _disabledSessionStore
            : persistentSessionStore {
    _session = _sessionStore.read();
  }

  static const Duration _accessTokenRefreshSkew = Duration(seconds: 30);
  static const AuthSessionStore _disabledSessionStore =
      DisabledAuthSessionStore();

  AppMode _mode;
  final AuthSessionStore _persistentSessionStore;
  AuthSessionStore _sessionStore;
  AuthSession? _session;

  AppMode get mode => _mode;

  bool get credentialsEnabled => _mode == AppMode.development;

  bool get hasSession => _session != null;

  AuthSession? get session => _session;

  AuthCredentials? get credentials => _session?.credentials;

  DateTime? get signedInAt => _session?.signedInAt;

  String? get accessToken => _session?.credentials.accessToken;

  String? get refreshToken => _session?.credentials.refreshToken;

  Future<void> setMode(AppMode nextMode) async {
    if (_mode == nextMode) {
      return;
    }

    _mode = nextMode;
    _session = null;
    _sessionStore = nextMode == AppMode.noAuth
        ? _disabledSessionStore
        : _persistentSessionStore;
    await _sessionStore.clear();
  }

  Future<void> storeSession(AuthSession session) async {
    _session = session;
    await _sessionStore.write(session);
  }

  Future<void> clearSession() async {
    _session = null;
    await _sessionStore.clear();
  }

  Future<Map<String, String>> buildAuthHeaders({
    required Future<AuthSession> Function(AuthSession session) refreshSession,
  }) async {
    if (_mode == AppMode.noAuth) {
      return const {};
    }

    final session = _session;
    if (session == null) {
      throw StateError('未登录，请先登录');
    }

    final readySession = await _ensureAuthSession(
      session,
      refreshSession: refreshSession,
    );
    final authHeaders = readySession.credentials.toAuthHeaders();
    if (!authHeaders.isReadyForHttp) {
      await clearSession();
      throw StateError('登录信息已失效，请重新登录');
    }
    return authHeaders.toHttpHeaders();
  }

  Future<AuthSession> _ensureAuthSession(
    AuthSession session, {
    required Future<AuthSession> Function(AuthSession session) refreshSession,
  }) async {
    final credentials = session.credentials;
    final now = DateTime.now();

    if (credentials.isAccessTokenUsable(now, skew: _accessTokenRefreshSkew)) {
      return session;
    }

    if (!credentials.isRefreshTokenUsable(now)) {
      await clearSession();
      throw StateError('凭证已失效，请重新登录');
    }

    AuthSession refreshed;
    try {
      refreshed = await refreshSession(session);
    } catch (_) {
      await clearSession();
      throw StateError('登录信息已失效，请重新登录');
    }

    if (!refreshed.credentials.hasAccessToken ||
        !refreshed.credentials.hasRefreshToken) {
      await clearSession();
      throw StateError('登录信息已失效，请重新登录');
    }

    final refreshedHeaders = refreshed.credentials.toAuthHeaders();
    if (!refreshedHeaders.isReadyForHttp) {
      await clearSession();
      throw StateError('登录信息已失效，请重新登录');
    }

    _session = refreshed;
    await _sessionStore.write(refreshed);
    return refreshed;
  }
}