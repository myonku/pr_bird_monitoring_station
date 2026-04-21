package appclient_business_dto

// ClientUserProfileRequest 是客户端用户资料查询请求载荷。
type ClientUserProfileRequest struct {
	Identifier string `json:"identifier"`
}

// ClientRegisterRequest 是客户端注册请求载荷。
type ClientRegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Password string `json:"password"`
}

// ClientHomeSnapshotRequest 是首页概览请求载荷。
type ClientHomeSnapshotRequest struct {
	DeviceID string `json:"device_id"`
}

// ClientRecordStationOptionsRequest 是记录页站点选项请求载荷。
type ClientRecordStationOptionsRequest struct {
	IncludeOffline bool `json:"include_offline"`
}

// ClientRecordsCursorRequest 是记录页游标分页请求载荷。
type ClientRecordsCursorRequest struct {
	StartAtMs     int64   `json:"start_at_ms"`
	EndAtMs       int64   `json:"end_at_ms"`
	DeviceID      string  `json:"device_id"`
	Keyword       string  `json:"keyword"`
	ConfidenceMin float64 `json:"confidence_min"`
	Cursor        string  `json:"cursor"`
	Limit         int     `json:"limit"`
	Sort          string  `json:"sort"`
}

// ClientWeeklyTrendRequest 是周趋势请求载荷。
type ClientWeeklyTrendRequest struct {
	Days     int    `json:"days"`
	DeviceID string `json:"device_id"`
}

// ClientRangeSummaryRequest 是时间段统计请求载荷。
type ClientRangeSummaryRequest struct {
	StartAtMs int64  `json:"start_at_ms"`
	EndAtMs   int64  `json:"end_at_ms"`
	DeviceID  string `json:"device_id"`
}
