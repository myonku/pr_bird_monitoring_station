package edge_server_business_dto

// EdgeEventUploadResponse 是边缘事件上传的 ACK/结果载荷。
type EdgeEventUploadResponse struct {
	Accepted     bool   `json:"accepted"`
	Status       string `json:"status"`
	RecordID     string `json:"record_id"`
	Spooled      bool   `json:"spooled"`
	Message      string `json:"message"`
	ErrorCode    string `json:"error_code"`
	ErrorMessage string `json:"error_message"`
}
