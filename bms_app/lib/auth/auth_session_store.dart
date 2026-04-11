import 'package:bms_app/auth/auth_models.dart';

abstract class AuthSessionStore {
  AuthSession? read();

  Future<void> write(AuthSession session);

  Future<void> clear();
}

class MemoryAuthSessionStore implements AuthSessionStore {
  MemoryAuthSessionStore();

  AuthSession? _session;

  @override
  AuthSession? read() => _session;

  @override
  Future<void> write(AuthSession session) async {
    _session = session;
  }

  @override
  Future<void> clear() async {
    _session = null;
  }
}

class DisabledAuthSessionStore implements AuthSessionStore {
  const DisabledAuthSessionStore();

  @override
  AuthSession? read() => null;

  @override
  Future<void> write(AuthSession session) async {}

  @override
  Future<void> clear() async {}
}
