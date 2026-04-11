abstract class AuthTokenSource {
  bool get credentialsEnabled;

  String? get accessToken;

  String? get refreshToken;

  Map<String, String> buildAuthHeaders();
}
