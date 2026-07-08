class ClientSignInRequest {
  const ClientSignInRequest({required this.identifier, required this.password});

  final String identifier;
  final String password;
}

class ClientRefreshSessionRequest {
  const ClientRefreshSessionRequest({
    required this.sessionId,
    required this.refreshToken,
    required this.tokenId,
    required this.tokenFamilyId,
    required this.principalId,
    this.scopes = const [],
  });

  final String sessionId;
  final String refreshToken;
  final String tokenId;
  final String tokenFamilyId;
  final String principalId;
  final List<String> scopes;
}

class ClientAuthCredentialsResponse {
  const ClientAuthCredentialsResponse({
    required this.accessToken,
    required this.refreshToken,
    required this.downstreamToken,
    required this.tokenType,
    required this.sessionId,
    required this.tokenId,
    required this.principalId,
    required this.tokenFamilyId,
    required this.scopes,
    required this.issuedAtMs,
    required this.accessExpiresAtMs,
    required this.refreshExpiresAtMs,
    required this.persisted,
  });

  final String accessToken;
  final String refreshToken;
  final String downstreamToken;
  final String tokenType;
  final String sessionId;
  final String tokenId;
  final String principalId;
  final String tokenFamilyId;
  final List<String> scopes;
  final int issuedAtMs;
  final int accessExpiresAtMs;
  final int refreshExpiresAtMs;
  final bool persisted;
}

class ClientUserProfileRequest {
  const ClientUserProfileRequest({required this.identifier});

  final String identifier;
}

class ClientRegisterRequest {
  const ClientRegisterRequest({
    required this.username,
    required this.password,
    this.email = '',
    this.phone = '',
  });

  final String username;
  final String email;
  final String phone;
  final String password;
}

class ClientHomeSnapshotRequest {
  const ClientHomeSnapshotRequest({this.deviceId});

  final String? deviceId;
}

class ClientRecordStationOptionsRequest {
  const ClientRecordStationOptionsRequest({this.includeOffline});

  final bool? includeOffline;
}

class ClientRecordsCursorRequest {
  const ClientRecordsCursorRequest({
    this.startAtMs,
    this.endAtMs,
    this.deviceId,
    this.keyword,
    this.confidenceMin,
    this.cursor,
    this.limit = 20,
    this.sort = 'captured_at_ms_desc',
  });

  final int? startAtMs;
  final int? endAtMs;
  final String? deviceId;
  final String? keyword;
  final double? confidenceMin;
  final String? cursor;
  final int limit;
  final String sort;
}

// ── Chat request DTOs ──────────────────────────────────────────────

class ChatImageRef {
  const ChatImageRef({
    this.imageId = '',
    this.data = '',
    this.mimeType = 'image/jpeg',
    this.filename = '',
  });

  final String imageId;
  final String data;
  final String mimeType;
  final String filename;
}

class ChatSendRequest {
  const ChatSendRequest({
    required this.sessionId,
    required this.userId,
    required this.text,
    this.images = const [],
    this.locale = 'zh-CN',
    this.timezone = 'Asia/Shanghai',
    this.traceId = '',
  });

  final String sessionId;
  final String userId;
  final String text;
  final List<ChatImageRef> images;
  final String locale;
  final String timezone;
  final String traceId;
}

class ChatSessionListRequest {
  const ChatSessionListRequest({
    required this.userId,
    this.limit = 20,
    this.offset = 0,
  });

  final String userId;
  final int limit;
  final int offset;
}

class ChatSessionGetRequest {
  const ChatSessionGetRequest({
    required this.sessionId,
    required this.userId,
    this.messageLimit = 50,
  });

  final String sessionId;
  final String userId;
  final int messageLimit;
}

class ChatSessionDeleteRequest {
  const ChatSessionDeleteRequest({
    required this.sessionId,
    required this.userId,
  });

  final String sessionId;
  final String userId;
}

class ChatSessionCreateRequest {
  const ChatSessionCreateRequest({
    required this.userId,
    this.title = '',
  });

  final String userId;
  final String title;
}

class ClientWeeklyTrendRequest {
  const ClientWeeklyTrendRequest({this.days = 7, this.deviceId});

  final int days;
  final String? deviceId;
}

class ClientRangeSummaryRequest {
  const ClientRangeSummaryRequest({
    required this.startAtMs,
    required this.endAtMs,
    this.deviceId,
  });

  final int startAtMs;
  final int endAtMs;
  final String? deviceId;
}
