import 'package:flutter_test/flutter_test.dart';

import 'package:bms_app/credential_manager/credential_manager.dart';
import 'package:bms_app/models/auth_models.dart';
import 'package:bms_app/models/common.dart';
import 'package:bms_app/storage/auth_stores.dart';

void main() {
  test('refresh transient failure keeps existing session', () async {
    final manager = MonitoringCredentialManager(
      initialMode: AppMode.development,
      sessionStore: MemoryAuthSessionStore(),
    );
    final now = DateTime.now();

    await manager.storeSession(
      AuthSession(
        loginIdentifier: 'example_user',
        mode: AppMode.development,
        signedInAt: now.subtract(const Duration(minutes: 5)),
        credentials: AuthCredentials(
          accessToken: 'expired-access',
          refreshToken: 'valid-refresh',
          tokenType: 'access',
          sessionId: 'session-id',
          tokenId: 'token-id',
          principalId: 'principal-id',
          tokenFamilyId: 'family-id',
          scopes: const ['client:read'],
          issuedAtMs: now
              .subtract(const Duration(minutes: 10))
              .millisecondsSinceEpoch,
          accessExpiresAtMs: now
              .subtract(const Duration(seconds: 1))
              .millisecondsSinceEpoch,
          refreshExpiresAtMs: now
              .add(const Duration(hours: 24))
              .millisecondsSinceEpoch,
          persisted: true,
        ),
      ),
    );

    await expectLater(
      () => manager.buildAuthHeaders(
        refreshSession: (_) async {
          throw Exception('temporary outage');
        },
      ),
      throwsA(
        isA<StateError>().having(
          (error) => error.message,
          'message',
          contains('会话刷新失败'),
        ),
      ),
    );

    expect(manager.hasSession, isTrue);
    expect(manager.session, isNotNull);
    expect(manager.refreshToken, 'valid-refresh');
  });

  test('refresh merges missing fields from previous credentials', () async {
    final manager = MonitoringCredentialManager(
      initialMode: AppMode.development,
      sessionStore: MemoryAuthSessionStore(),
    );
    final now = DateTime.now();

    final initialSession = AuthSession(
      loginIdentifier: 'example_user',
      mode: AppMode.development,
      signedInAt: now.subtract(const Duration(minutes: 20)),
      credentials: AuthCredentials(
        accessToken: 'expired-access',
        refreshToken: 'refresh-1',
        tokenType: 'access',
        sessionId: 'session-1',
        tokenId: 'token-1',
        principalId: 'principal-1',
        tokenFamilyId: 'family-1',
        scopes: const ['client:read'],
        issuedAtMs: now
            .subtract(const Duration(minutes: 20))
            .millisecondsSinceEpoch,
        accessExpiresAtMs: now
            .subtract(const Duration(seconds: 1))
            .millisecondsSinceEpoch,
        refreshExpiresAtMs: now
            .add(const Duration(hours: 20))
            .millisecondsSinceEpoch,
        persisted: true,
      ),
    );
    await manager.storeSession(initialSession);

    final refreshedSession = AuthSession(
      loginIdentifier: '',
      mode: AppMode.development,
      signedInAt: initialSession.signedInAt,
      credentials: AuthCredentials(
        accessToken: 'new-access',
        refreshToken: '',
        tokenType: '',
        sessionId: '',
        tokenId: '',
        principalId: '',
        tokenFamilyId: '',
        scopes: const [],
        issuedAtMs: now.millisecondsSinceEpoch,
        accessExpiresAtMs: now
            .add(const Duration(minutes: 5))
            .millisecondsSinceEpoch,
        refreshExpiresAtMs: 0,
        persisted: false,
      ),
    );

    final headers = await manager.buildAuthHeaders(
      refreshSession: (_) async => refreshedSession,
    );

    expect(headers['Authorization'], 'Bearer new-access');
    expect(headers['x-downstream-session-id'], 'session-1');
    expect(headers['x-downstream-token-id'], 'token-1');
    expect(headers['x-downstream-principal'], 'principal-1');

    final merged = manager.session;
    expect(merged, isNotNull);
    expect(merged!.loginIdentifier, 'example_user');
    expect(merged.credentials.refreshToken, 'refresh-1');
    expect(
      merged.credentials.refreshExpiresAtMs,
      initialSession.credentials.refreshExpiresAtMs,
    );
    expect(merged.credentials.persisted, isTrue);
  });
}
