import 'package:flutter/material.dart';

import 'package:bms_app/auth/auth_models.dart';
import 'package:bms_app/auth/auth_session_store.dart';
import 'package:bms_app/auth/auth_service.dart';
import 'package:bms_app/auth/auth_token_source.dart';
import 'package:bms_app/models/monitoring_models.dart';

class AuthController extends ChangeNotifier implements AuthTokenSource {
  AuthController({
    required AuthService service,
    AuthSessionStore? sessionStore,
    AppMode initialMode = AppMode.development,
  }) : _service = service,
       _sessionStore = sessionStore ?? MemoryAuthSessionStore(),
       _mode = initialMode {
    if (_mode == AppMode.noAuth) {
      _sessionStore = const DisabledAuthSessionStore();
    }
    _session = _sessionStore.read();
  }

  final AuthService _service;
  AuthSessionStore _sessionStore;
  AppMode _mode;
  AuthSession? _session;

  AppMode get mode => _mode;
  bool get isAuthenticated => _session != null;
  AppUser get activeUser => _session?.user ?? _service.defaultUser;
  AuthCredentials? get credentials => _session?.credentials;
  DateTime? get signedInAt => _session?.signedInAt;

  String get statusLabel => isAuthenticated ? '已登录' : '未登录';

  String get credentialPolicyLabel => switch (_mode) {
    AppMode.development => 'development: 凭证启用',
    AppMode.noAuth => 'no-auth: 空凭证',
  };

  String get credentialStorageLabel => switch (_mode) {
    AppMode.development =>
      _session?.credentials.persisted == true ? '已缓存凭证' : '未缓存凭证',
    AppMode.noAuth => '已禁用',
  };

  @override
  bool get credentialsEnabled => _mode == AppMode.development;

  @override
  String? get accessToken => _session?.credentials.accessToken;

  @override
  String? get refreshToken => _session?.credentials.refreshToken;

  @override
  Map<String, String> buildAuthHeaders() =>
      _session?.credentials.buildAuthHeaders() ?? const {};

  void switchMode(AppMode nextMode) {
    if (_mode == nextMode) {
      return;
    }

    _mode = nextMode;
    _session = null;
    _sessionStore = nextMode == AppMode.noAuth
        ? const DisabledAuthSessionStore()
        : MemoryAuthSessionStore();
    notifyListeners();
  }

  Future<void> signIn({
    required String username,
    required String password,
  }) async {
    final session = await _service.signIn(
      username: username,
      password: password,
      mode: _mode,
    );

    _session = session;
    await _sessionStore.write(session);
    notifyListeners();
  }

  Future<void> signOut() async {
    final session = _session;
    _session = null;
    await _service.signOut(session: session);
    await _sessionStore.clear();
    notifyListeners();
  }
}
