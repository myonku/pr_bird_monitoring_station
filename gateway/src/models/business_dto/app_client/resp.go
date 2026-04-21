package appclient_business_dto

// ClientUserProfileResponse 是客户端用户资料响应载荷。
type ClientUserProfileResponse struct {
	UserID      string `json:"user_id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Name        string `json:"name"`
	Role        string `json:"role"`
	Email       string `json:"email"`
	Phone       string `json:"phone"`
	AvatarB64   string `json:"avatar_b64"`
}

// ClientRegisterResponse 是客户端注册响应载荷。
type ClientRegisterResponse struct {
	Ok        bool   `json:"ok"`
	ErrorCode string `json:"error_code"`
	Message   string `json:"message"`
}

// ClientUploadStationSummaryResponse 是首页热点站点摘要响应载荷。
type ClientUploadStationSummaryResponse struct {
	DeviceID    string `json:"device_id"`
	DeviceName  string `json:"device_name"`
	UploadCount int    `json:"upload_count"`
}

// ClientLatestUploadSummaryResponse 是首页最近上传摘要响应载荷。
type ClientLatestUploadSummaryResponse struct {
	DeviceID        string `json:"device_id"`
	DeviceName      string `json:"device_name"`
	UploadedAtMs    *int64 `json:"uploaded_at_ms"`
	UploadedAtLabel string `json:"uploaded_at_label"`
}

// ClientRecordStationOptionResponse 是站点选项响应载荷。
type ClientRecordStationOptionResponse struct {
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name"`
	Online     bool   `json:"online"`
	Status     string `json:"status"`
}

// ClientBirdRecordResponse 是单条监测记录响应载荷。
type ClientBirdRecordResponse struct {
	ID               string            `json:"id"`
	Species          string            `json:"species"`
	ScientificName   string            `json:"scientific_name"`
	CapturedAtMs     int64             `json:"captured_at_ms"`
	CapturedAtLabel  string            `json:"captured_at_label"`
	DeviceID         string            `json:"device_id"`
	DeviceName       string            `json:"device_name"`
	Confidence       float64           `json:"confidence"`
	TemperatureC     *float64          `json:"temperature_c"`
	HumidityPct      *int              `json:"humidity_pct"`
	UploadSummary    string            `json:"upload_summary"`
	SpeciesIntro     string            `json:"species_intro"`
	ImageB64         string            `json:"image_b64"`
	MediaRefs        []string          `json:"media_refs"`
	ProcessingSource string            `json:"processing_source"`
	ModelVersion     string            `json:"model_version"`
	RecordStatus     string            `json:"record_status"`
	SummaryText      string            `json:"summary_text"`
	SpeciesEntityID  string            `json:"species_entity_id"`
	Metadata         map[string]string `json:"metadata"`
}

// ClientTrendPointResponse 是趋势点响应载荷。
type ClientTrendPointResponse struct {
	Label  string `json:"label"`
	Value  int    `json:"value"`
	DateMs *int64 `json:"date_ms"`
}

// ClientSpeciesShareResponse 是物种占比响应载荷。
type ClientSpeciesShareResponse struct {
	Label           string  `json:"label"`
	Value           int     `json:"value"`
	Ratio           float64 `json:"ratio"`
	SpeciesEntityID string  `json:"species_entity_id"`
	ColorHex        string  `json:"color_hex"`
}

// ClientPeakDayResponse 是峰值日期响应载荷。
type ClientPeakDayResponse struct {
	Label  string `json:"label"`
	Value  int    `json:"value"`
	DateMs *int64 `json:"date_ms"`
}

// ClientPeakDeviceSummaryResponse 是峰值站点响应载荷。
type ClientPeakDeviceSummaryResponse struct {
	DeviceID    string `json:"device_id"`
	DeviceName  string `json:"device_name"`
	RecordCount int    `json:"record_count"`
}

// ClientDashboardSnapshotResponse 是首页概览响应载荷。
type ClientDashboardSnapshotResponse struct {
	TodayRecognitionCount int                                `json:"today_recognition_count"`
	TodayUploadCount      int                                `json:"today_upload_count"`
	OnlineStationCount    int                                `json:"online_station_count"`
	ActiveStationCount    int                                `json:"active_station_count"`
	TopUploadStation      ClientUploadStationSummaryResponse `json:"top_upload_station"`
	LatestUpload          ClientLatestUploadSummaryResponse  `json:"latest_upload"`
	RecentRecords         []ClientBirdRecordResponse         `json:"recent_records"`
}

// ClientRecordsCursorResponse 是记录页游标响应载荷。
type ClientRecordsCursorResponse struct {
	Items      []ClientBirdRecordResponse `json:"items"`
	NextCursor string                     `json:"next_cursor"`
	HasMore    bool                       `json:"has_more"`
}

// ClientWeeklyTrendResponse 是最近七日趋势响应载荷。
type ClientWeeklyTrendResponse struct {
	Series []ClientTrendPointResponse `json:"series"`
	Total  int                        `json:"total"`
}

// ClientRangeSummaryResponse 是时间段统计响应载荷。
type ClientRangeSummaryResponse struct {
	TotalCount        int                             `json:"total_count"`
	DailyDistribution []ClientTrendPointResponse      `json:"daily_distribution"`
	SpeciesShares     []ClientSpeciesShareResponse    `json:"species_shares"`
	PeakDay           ClientPeakDayResponse           `json:"peak_day"`
	PeakDevice        ClientPeakDeviceSummaryResponse `json:"peak_device"`
}
