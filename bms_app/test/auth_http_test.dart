import 'package:flutter_test/flutter_test.dart';

import 'package:bms_app/models/transport/client_req_dto.dart';
import 'package:bms_app/transport/http_client.dart';

const String _gatewayBaseUrl = 'http://127.0.0.1:8080';
const String _loginIdentifier = 'example_user';
const String _loginPassword = '123456';

void main() {
  test('login and refresh auth credentials through the gateway', () async {
    final client = HttpMonitoringClient(baseUrl: _gatewayBaseUrl);

    final signInResponse = await client.signIn(
      const ClientSignInRequest(
        identifier: _loginIdentifier,
        password: _loginPassword,
      ),
    );

    _expectSignedInCredentialBundle(signInResponse);
    expect(signInResponse.tokenType, 'access');
    expect(signInResponse.persisted, isFalse);

    final refreshResponse = await client.refreshSession(
      ClientRefreshSessionRequest(
        sessionId: signInResponse.sessionId,
        refreshToken: signInResponse.refreshToken,
        tokenId: signInResponse.tokenId,
        tokenFamilyId: signInResponse.tokenFamilyId,
        principalId: signInResponse.principalId,
        scopes: signInResponse.scopes,
      ),
    );

    _expectRefreshedCredentialBundle(refreshResponse);
    expect(refreshResponse.persisted, isFalse);
    expect(refreshResponse.principalId, signInResponse.principalId);
    expect(
      refreshResponse.issuedAtMs,
      greaterThanOrEqualTo(signInResponse.issuedAtMs),
    );
    expect(
      refreshResponse.accessToken != signInResponse.accessToken ||
          refreshResponse.refreshToken != signInResponse.refreshToken,
      isTrue,
    );
  });
}

void _expectSignedInCredentialBundle(ClientAuthCredentialsResponse response) {
  expect(response.accessToken, isNotEmpty);
  expect(response.refreshToken, isNotEmpty);
  expect(response.tokenType, isNotEmpty);
  expect(response.sessionId, isNotEmpty);
  expect(response.tokenId, isNotEmpty);
  expect(response.principalId, isNotEmpty);
  expect(response.tokenFamilyId, isNotEmpty);
  expect(response.issuedAtMs, greaterThan(0));
  expect(response.accessExpiresAtMs, greaterThan(response.issuedAtMs));
  expect(response.refreshExpiresAtMs, greaterThanOrEqualTo(0));
}

void _expectRefreshedCredentialBundle(ClientAuthCredentialsResponse response) {
  expect(response.accessToken, isNotEmpty);
  expect(response.refreshToken, isNotEmpty);
  expect(response.tokenType, isNotEmpty);
  expect(response.sessionId, isNotEmpty);
  expect(response.tokenId, isNotEmpty);
  expect(response.principalId, isNotEmpty);
  expect(response.tokenFamilyId, isNotEmpty);
  expect(response.issuedAtMs, greaterThan(0));
  expect(response.accessExpiresAtMs, greaterThan(response.issuedAtMs));
  expect(response.refreshExpiresAtMs, greaterThan(response.accessExpiresAtMs));
}
