package edge_server_business_dto

// EdgeTemperatureHumiditySnapshot 是边缘端环境快照载荷。
type EdgeTemperatureHumiditySnapshot struct {
	TemperatureC   *float64       `json:"temperature_c"`
	HumidityPct    *int           `json:"humidity_pct"`
	Source         string         `json:"source"`
	SensorSnapshot map[string]any `json:"sensor_snapshot"`
	CapturedAtMs   int64          `json:"captured_at_ms"`
}

// EdgeCaptureContext 是边缘端采集上下文载荷。
type EdgeCaptureContext struct {
	DeviceID            string                           `json:"device_id"`
	DeviceName          string                           `json:"device_name"`
	LocationName        string                           `json:"location_name"`
	TriggerType         string                           `json:"trigger_type"`
	SensorSnapshot      map[string]any                   `json:"sensor_snapshot"`
	EnvironmentSnapshot *EdgeTemperatureHumiditySnapshot `json:"environment_snapshot"`
	CapturedAtMs        int64                            `json:"captured_at_ms"`
}

// EdgeImagePayload 是边缘端图像元数据载荷。
type EdgeImagePayload struct {
	ImageID        string `json:"image_id"`
	Format         string `json:"format"`
	Width          *int   `json:"width"`
	Height         *int   `json:"height"`
	ChecksumSHA256 string `json:"checksum_sha256"`
}

// EdgeDetectionBox 是检测框结果载荷。
type EdgeDetectionBox struct {
	Label      string  `json:"label"`
	Confidence float64 `json:"confidence"`
	X1         float64 `json:"x1"`
	Y1         float64 `json:"y1"`
	X2         float64 `json:"x2"`
	Y2         float64 `json:"y2"`
}

// EdgeDetectionResult 是检测阶段结果载荷。
type EdgeDetectionResult struct {
	Success        bool               `json:"success"`
	Boxes          []EdgeDetectionBox `json:"boxes"`
	LatencyMs      *int64             `json:"latency_ms"`
	Reason         *string            `json:"reason"`
	ModelSignature *string            `json:"model_signature"`
}

// EdgeClassificationHit 是分类命中结果载荷。
type EdgeClassificationHit struct {
	Label      string  `json:"label"`
	Confidence float64 `json:"confidence"`
}

// EdgeClassificationResult 是分类阶段结果载荷。
type EdgeClassificationResult struct {
	Success        bool                    `json:"success"`
	Top1Label      *string                 `json:"top1_label"`
	Top1Confidence *float64                `json:"top1_confidence"`
	TopK           []EdgeClassificationHit `json:"topk"`
	LatencyMs      *int64                  `json:"latency_ms"`
	Reason         *string                 `json:"reason"`
	ModelSignature *string                 `json:"model_signature"`
}

// EdgeTwoStageInferenceResult 是两阶段推理结果载荷。
type EdgeTwoStageInferenceResult struct {
	Success                  bool                      `json:"success"`
	Stage                    string                    `json:"stage"`
	Detection                EdgeDetectionResult       `json:"detection"`
	Classification           *EdgeClassificationResult `json:"classification"`
	CropApplied              bool                      `json:"crop_applied"`
	CropBox                  map[string]float64        `json:"crop_box"`
	DetectorModelVersion     *string                   `json:"detector_model_version"`
	ClassifierModelVersion   *string                   `json:"classifier_model_version"`
	DetectorModelSignature   *string                   `json:"detector_model_signature"`
	ClassifierModelSignature *string                   `json:"classifier_model_signature"`
	Reason                   *string                   `json:"reason"`
}

// EdgeEventUploadRequest 是边缘事件上传的业务载荷。
type EdgeEventUploadRequest struct {
	EventID              string                       `json:"event_id"`
	TraceID              string                       `json:"trace_id"`
	RequiresServerAssist bool                         `json:"requires_server_assist"`
	Context              EdgeCaptureContext           `json:"context"`
	Image                EdgeImagePayload             `json:"image"`
	ImageB64             string                       `json:"image_b64"`
	LocalInference       *EdgeTwoStageInferenceResult `json:"local_inference"`
	Metadata             map[string]any               `json:"metadata"`
}
