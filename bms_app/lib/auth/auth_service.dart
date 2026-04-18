import 'package:bms_app/auth/auth_models.dart';
import 'package:bms_app/data_source/monitoring_repository.dart';
import 'package:bms_app/models/monitoring_models.dart';

abstract class AuthService {
  AppUser get defaultUser;

  Future<AppUser?> fetchUserProfile(String identifier);

  Future<RegistrationResult> registerUser({
    required String username,
    String email = '',
    String phone = '',
    required String password,
  });

  Future<AuthSession> signIn({
    required String identifier,
    required String password,
    required AppMode mode,
  });

  Future<void> signOut({AuthSession? session});
}

class MockAuthService implements AuthService {
  const MockAuthService(this.repository);

  final MonitoringRepository repository;

  @override
  AppUser get defaultUser => repository.defaultUser;

  @override
  Future<AppUser?> fetchUserProfile(String identifier) async {
    final normalized = identifier.trim();
    if (normalized.isEmpty) {
      return repository.defaultUser;
    }

    return repository.fetchUserProfile(normalized);
  }

  @override
  Future<RegistrationResult> registerUser({
    required String username,
    String email = '',
    String phone = '',
    required String password,
  }) {
    return repository.registerUser(
      username: username,
      email: email,
      phone: phone,
      password: password,
    );
  }

  @override
  Future<AuthSession> signIn({
    required String identifier,
    required String password,
    required AppMode mode,
  }) async {
    final now = DateTime.now();
    final passwordSeed = password.trim().isEmpty
        ? 'blank'
        : password.trim().hashCode.toUnsigned(32).toRadixString(16);

    final credentials = mode == AppMode.development
        ? AuthCredentials(
            accessToken:
                'mock-access-${now.millisecondsSinceEpoch}-$passwordSeed',
            refreshToken:
                'mock-refresh-${now.millisecondsSinceEpoch}-$passwordSeed',
            downstreamToken:
                'mock-downstream-${now.millisecondsSinceEpoch}-$passwordSeed',
            tokenType: 'Bearer',
            sessionId: 'mock-session-${now.millisecondsSinceEpoch}',
            issuedAtMs: now.millisecondsSinceEpoch,
            accessExpiresAtMs: now
                .add(const Duration(hours: 2))
                .millisecondsSinceEpoch,
            refreshExpiresAtMs: now
                .add(const Duration(days: 30))
                .millisecondsSinceEpoch,
            persisted: true,
          )
        : const AuthCredentials();

    return AuthSession(
      loginIdentifier: identifier.trim(),
      credentials: credentials,
      mode: mode,
      signedInAt: now,
    );
  }

  @override
  Future<void> signOut({AuthSession? session}) async {}
}
