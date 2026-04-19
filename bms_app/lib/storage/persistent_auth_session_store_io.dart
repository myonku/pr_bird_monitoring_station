import 'dart:convert';
import 'dart:io';

import 'package:bms_app/models/auth_models.dart';
import 'package:bms_app/models/common.dart';
import 'package:bms_app/storage/storage.dart';

class PersistentAuthSessionStore implements AuthSessionStore {
  PersistentAuthSessionStore({String? storageFilePath})
    : _file = File(storageFilePath ?? _defaultStorageFilePath()) {
    _session = _readSession();
  }

  final File _file;
  AuthSession? _session;

  @override
  AuthSession? read() => _session;

  @override
  Future<void> write(AuthSession session) async {
    _session = session;
    try {
      final parent = _file.parent;
      if (!parent.existsSync()) {
        parent.createSync(recursive: true);
      }
      await _file.writeAsString(jsonEncode(_encodeSession(session)));
    } catch (_) {
      // Keep the in-memory session even if disk persistence fails.
    }
  }

  @override
  Future<void> clear() async {
    _session = null;
    try {
      if (_file.existsSync()) {
        await _file.delete();
      }
    } catch (_) {
      // Ignore persistence cleanup errors.
    }
  }

  AuthSession? _readSession() {
    try {
      if (!_file.existsSync()) {
        return null;
      }
      final raw = _file.readAsStringSync();
      if (raw.trim().isEmpty) {
        return null;
      }
      return _decodeSession(jsonDecode(raw));
    } catch (_) {
      return null;
    }
  }

  static Map<String, dynamic> _encodeSession(AuthSession session) {
    return <String, dynamic>{
      'loginIdentifier': session.loginIdentifier,
      'mode': session.mode.name,
      'signedInAtMs': session.signedInAt.millisecondsSinceEpoch,
      'credentials': <String, dynamic>{
        'accessToken': session.credentials.accessToken,
        'refreshToken': session.credentials.refreshToken,
        'downstreamToken': session.credentials.downstreamToken,
        'tokenType': session.credentials.tokenType,
        'sessionId': session.credentials.sessionId,
        'tokenId': session.credentials.tokenId,
        'principalId': session.credentials.principalId,
        'tokenFamilyId': session.credentials.tokenFamilyId,
        'scopes': session.credentials.scopes,
        'issuedAtMs': session.credentials.issuedAtMs,
        'accessExpiresAtMs': session.credentials.accessExpiresAtMs,
        'refreshExpiresAtMs': session.credentials.refreshExpiresAtMs,
        'persisted': session.credentials.persisted,
      },
    };
  }

  static AuthSession? _decodeSession(dynamic value) {
    if (value is! Map) {
      return null;
    }

    final map = value.map((key, entry) => MapEntry(key.toString(), entry));
    final loginIdentifier = _string(map['loginIdentifier']);
    final modeName = _string(map['mode']);
    final signedInAtMs = _int(map['signedInAtMs']);
    final credentialsMap = map['credentials'];
    if (loginIdentifier.isEmpty || modeName.isEmpty || signedInAtMs == null) {
      return null;
    }
    if (credentialsMap is! Map) {
      return null;
    }

    AppMode? mode;
    try {
      mode = AppMode.values.byName(modeName);
    } catch (_) {
      mode = null;
    }
    if (mode == null) {
      return null;
    }

    final normalizedCredentials =
        credentialsMap.map((key, entry) => MapEntry(key.toString(), entry));
    return AuthSession(
      loginIdentifier: loginIdentifier,
      mode: mode,
      signedInAt: DateTime.fromMillisecondsSinceEpoch(signedInAtMs),
      credentials: AuthCredentials(
        accessToken: _nullableString(normalizedCredentials['accessToken']),
        refreshToken: _nullableString(normalizedCredentials['refreshToken']),
        downstreamToken: _nullableString(normalizedCredentials['downstreamToken']),
        tokenType: _string(normalizedCredentials['tokenType']).isEmpty
            ? 'access'
            : _string(normalizedCredentials['tokenType']),
        sessionId: _nullableString(normalizedCredentials['sessionId']),
        tokenId: _nullableString(normalizedCredentials['tokenId']),
        principalId: _nullableString(normalizedCredentials['principalId']),
        tokenFamilyId: _nullableString(normalizedCredentials['tokenFamilyId']),
        scopes: _stringList(normalizedCredentials['scopes']),
        issuedAtMs: _int(normalizedCredentials['issuedAtMs']),
        accessExpiresAtMs: _int(normalizedCredentials['accessExpiresAtMs']),
        refreshExpiresAtMs: _int(normalizedCredentials['refreshExpiresAtMs']),
        persisted: _bool(normalizedCredentials['persisted']),
      ),
    );
  }

  static String _defaultStorageFilePath() {
    final baseDirectory = Platform.environment['APPDATA'] ??
        Platform.environment['LOCALAPPDATA'] ??
        Platform.environment['HOME'] ??
        Directory.current.path;
    return _joinPath(baseDirectory, 'bms_app_auth_session.json');
  }

  static String _joinPath(String left, String right) {
    final separator = Platform.pathSeparator;
    final normalizedLeft = left.endsWith(separator)
        ? left.substring(0, left.length - 1)
        : left;
    final normalizedRight = right.startsWith(separator)
        ? right.substring(1)
        : right;
    return '$normalizedLeft$separator$normalizedRight';
  }

  static String _string(dynamic value) => value?.toString().trim() ?? '';

  static String? _nullableString(dynamic value) {
    final text = _string(value);
    return text.isEmpty ? null : text;
  }

  static int? _int(dynamic value) {
    if (value == null) {
      return null;
    }
    if (value is int) {
      return value;
    }
    if (value is num) {
      return value.toInt();
    }
    return int.tryParse(value.toString());
  }

  static bool _bool(dynamic value) {
    if (value is bool) {
      return value;
    }
    if (value is num) {
      return value != 0;
    }
    final text = value?.toString().trim().toLowerCase() ?? '';
    return text == 'true' || text == '1' || text == 'yes';
  }

  static List<String> _stringList(dynamic value) {
    if (value is List) {
      return value
          .map((entry) => entry.toString().trim())
          .where((entry) => entry.isNotEmpty)
          .toList(growable: false);
    }
    if (value == null) {
      return const [];
    }
    final text = value.toString().trim();
    if (text.isEmpty) {
      return const [];
    }
    return text
        .split(',')
        .map((entry) => entry.trim())
        .where((entry) => entry.isNotEmpty)
        .toList(growable: false);
  }
}
