import 'package:bms_app/models/auth_models.dart';
import 'package:bms_app/storage/storage.dart';

class PersistentAuthSessionStore implements AuthSessionStore {
  PersistentAuthSessionStore({String? storageFilePath});

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
