import 'package:bms_app/models/auth_models.dart';
import 'package:bms_app/storage/storage.dart';

export 'persistent_auth_session_store_stub.dart'
    if (dart.library.io) 'persistent_auth_session_store_io.dart';

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
