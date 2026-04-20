class ClientUserProfileResponse {
  const ClientUserProfileResponse({
    required this.userId,
    required this.username,
    required this.displayName,
    required this.name,
    required this.role,
    required this.email,
    required this.phone,
    this.avatarB64 = '',
  });

  final String userId;
  final String username;
  final String displayName;
  final String name;
  final String role;
  final String email;
  final String phone;
  final String avatarB64;
}

class ClientRegisterResponse {
  const ClientRegisterResponse({
    required this.ok,
    this.errorCode = '',
    this.message = '',
  });

  final bool ok;
  final String errorCode;
  final String message;
}

class ClientUploadStationSummaryResponse {
  const ClientUploadStationSummaryResponse({
    required this.deviceId,
    required this.deviceName,
    required this.uploadCount,
  });

  final String deviceId;
  final String deviceName;
  final int uploadCount;
}

class ClientLatestUploadSummaryResponse {
  const ClientLatestUploadSummaryResponse({
    required this.deviceId,
    required this.deviceName,
    required this.uploadedAtMs,
    required this.uploadedAtLabel,
  });

  final String deviceId;
  final String deviceName;
  final int? uploadedAtMs;
  final String uploadedAtLabel;
}

class ClientRecordStationOptionResponse {
  const ClientRecordStationOptionResponse({
    required this.deviceId,
    required this.deviceName,
    required this.online,
    required this.status,
  });

  final String deviceId;
  final String deviceName;
  final bool online;
  final String status;
}

class ClientBirdRecordResponse {
  const ClientBirdRecordResponse({
    required this.id,
    required this.species,
    required this.scientificName,
    required this.capturedAtMs,
    required this.capturedAtLabel,
    required this.deviceId,
    required this.deviceName,
    required this.confidence,
    required this.temperatureC,
    required this.humidityPct,
    required this.uploadSummary,
    required this.speciesIntro,
    this.imageB64 = '',
    required this.mediaRefs,
    required this.processingSource,
    required this.modelVersion,
    required this.recordStatus,
    required this.summaryText,
    required this.speciesEntityId,
    required this.metadata,
  });

  final String id;
  final String species;
  final String scientificName;
  final int capturedAtMs;
  final String capturedAtLabel;
  final String deviceId;
  final String deviceName;
  final double confidence;
  final double? temperatureC;
  final int? humidityPct;
  final String uploadSummary;
  final String speciesIntro;
  final String imageB64;
  final List<String> mediaRefs;
  final String processingSource;
  final String modelVersion;
  final String recordStatus;
  final String summaryText;
  final String speciesEntityId;
  final Map<String, String> metadata;
}

class ClientTrendPointResponse {
  const ClientTrendPointResponse({
    required this.label,
    required this.value,
    this.dateMs,
  });

  final String label;
  final int value;
  final int? dateMs;
}

class ClientSpeciesShareResponse {
  const ClientSpeciesShareResponse({
    required this.label,
    required this.value,
    required this.ratio,
    required this.speciesEntityId,
    required this.colorHex,
  });

  final String label;
  final int value;
  final double ratio;
  final String speciesEntityId;
  final String colorHex;
}

class ClientPeakDayResponse {
  const ClientPeakDayResponse({
    required this.label,
    required this.value,
    this.dateMs,
  });

  final String label;
  final int value;
  final int? dateMs;
}

class ClientPeakDeviceSummaryResponse {
  const ClientPeakDeviceSummaryResponse({
    required this.deviceId,
    required this.deviceName,
    required this.recordCount,
  });

  final String deviceId;
  final String deviceName;
  final int recordCount;
}

class ClientDashboardSnapshotResponse {
  const ClientDashboardSnapshotResponse({
    required this.todayRecognitionCount,
    required this.todayUploadCount,
    required this.onlineStationCount,
    required this.activeStationCount,
    required this.topUploadStation,
    required this.latestUpload,
    required this.recentRecords,
  });

  final int todayRecognitionCount;
  final int todayUploadCount;
  final int onlineStationCount;
  final int activeStationCount;
  final ClientUploadStationSummaryResponse topUploadStation;
  final ClientLatestUploadSummaryResponse latestUpload;
  final List<ClientBirdRecordResponse> recentRecords;
}

class ClientRecordsCursorResponse {
  const ClientRecordsCursorResponse({
    required this.items,
    required this.nextCursor,
    required this.hasMore,
  });

  final List<ClientBirdRecordResponse> items;
  final String nextCursor;
  final bool hasMore;
}

class ClientWeeklyTrendResponse {
  const ClientWeeklyTrendResponse({required this.series, required this.total});

  final List<ClientTrendPointResponse> series;
  final int total;
}

class ClientRangeSummaryResponse {
  const ClientRangeSummaryResponse({
    required this.totalCount,
    required this.dailyDistribution,
    required this.speciesShares,
    required this.peakDay,
    required this.peakDevice,
  });

  final int totalCount;
  final List<ClientTrendPointResponse> dailyDistribution;
  final List<ClientSpeciesShareResponse> speciesShares;
  final ClientPeakDayResponse peakDay;
  final ClientPeakDeviceSummaryResponse peakDevice;
}
