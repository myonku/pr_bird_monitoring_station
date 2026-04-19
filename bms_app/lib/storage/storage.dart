import 'package:bms_app/models/auth_models.dart';

abstract class AuthSessionStore {
  AuthSession? read();

  Future<void> write(AuthSession session);

  Future<void> clear();
}


