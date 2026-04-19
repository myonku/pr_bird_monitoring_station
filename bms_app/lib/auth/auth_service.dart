import 'package:bms_app/models/auth_models.dart';
import 'package:bms_app/models/common.dart';

/// AuthService defines auth workflow semantics for the app layer.
///
/// The controller only depends on this contract so auth transport and token
/// sources can be replaced (mock/http) without touching page logic.
abstract class AuthService {
  AppUser get defaultUser;

  Future<AppUser?> fetchUserProfile(String identifier);

  Future<AuthSession> refreshSession(AuthSession session);

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
