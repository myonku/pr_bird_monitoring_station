import 'package:flutter/material.dart';

import 'package:bms_app/models/auth_models.dart';
import 'package:bms_app/auth/auth_service.dart';
import 'package:bms_app/credential_manager/credential_manager.dart';
import 'package:bms_app/models/common.dart';

class AuthController extends ChangeNotifier {
  AuthController({
    required AuthService service,
    required MonitoringCredentialManager credentials,
  }) : _service = service,
       _credentials = credentials,
       _activeUser = service.defaultUser;

  final AuthService _service;
  final MonitoringCredentialManager _credentials;
  late AppUser _activeUser;

  AppMode get mode => _credentials.mode;
  bool get isAuthenticated => _credentials.hasSession;
  AppUser get activeUser => _activeUser;
  AuthCredentials? get credentials => _credentials.credentials;
  DateTime? get signedInAt => _credentials.signedInAt;

  String get statusLabel => isAuthenticated ? '已登录' : '未登录';

  String get credentialPolicyLabel => switch (mode) {
    AppMode.development => '测试模式：凭证启用',
    AppMode.noAuth => '无认证模式：空凭证',
  };

  String get credentialStorageLabel => switch (mode) {
    AppMode.development =>
      _credentials.credentials?.persisted == true ? '已缓存凭证' : '未缓存凭证',
    AppMode.noAuth => '已禁用',
  };

  bool get credentialsEnabled => _credentials.credentialsEnabled;

  String? get accessToken => _credentials.accessToken;

  String? get refreshToken => _credentials.refreshToken;

  Future<Map<String, String>> buildAuthHeaders() {
    return _credentials.buildAuthHeaders(refreshSession: _service.refreshSession);
  }

  Future<void> switchMode(AppMode nextMode) async {
    if (mode == nextMode) {
      return;
    }

    await _credentials.setMode(nextMode);
    _activeUser = _service.defaultUser;
    notifyListeners();
  }

  Future<void> signIn({
    required String identifier,
    required String password,
  }) async {
    final session = await _service.signIn(
      identifier: identifier,
      password: password,
      mode: mode,
    );

    if (mode == AppMode.development &&
        (!session.credentials.hasAccessToken ||
            !session.credentials.hasRefreshToken ||
            !session.credentials.toAuthHeaders().isReadyForHttp)) {
      throw StateError('登录信息已失效，请重新登录');
    }

    AppUser? user;
    if (mode == AppMode.noAuth) {
      try {
        user = await _service.fetchUserProfile(identifier);
      } catch (_) {
        user = _service.defaultUser;
      }
    } else {
      user = await _service.fetchUserProfile(identifier);
    }

    _activeUser = user ?? _service.defaultUser;
    notifyListeners();
  }

  Future<RegistrationResult> register({
    required String username,
    String email = '',
    String phone = '',
    required String password,
  }) {
    return _service.registerUser(
      username: username,
      email: email,
      phone: phone,
      password: password,
    );
  }

  Future<void> signOut() async {
    final session = _credentials.session;
    _activeUser = _service.defaultUser;
    await _service.signOut(session: session);
    await _credentials.clearSession();
    notifyListeners();
  }
}
