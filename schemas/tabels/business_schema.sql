-- 业务域表结构（MySQL 8.0+）

-- 业务数据域：边缘接入、处理任务、识别结果、监测记录
-- 说明：业务展示态用户资料与边缘事件原始二进制内容由 Mongo 文档存储，本文件只保留关系型索引与业务主记录。

CREATE TABLE IF NOT EXISTS business_edge_events (
  event_id CHAR(36) NOT NULL,
  device_entity_id CHAR(36) NOT NULL,
  occurred_at DATETIME(3) NOT NULL,
  received_at DATETIME(3) NOT NULL,
  payload_version VARCHAR(32) NOT NULL,
  payload_type VARCHAR(32) NOT NULL,
  payload_mongo_document_id VARCHAR(128) NOT NULL,
  transport_meta JSON NOT NULL,
  metadata JSON NOT NULL,
  created_at DATETIME(3) NOT NULL,
  updated_at DATETIME(3) NOT NULL,
  PRIMARY KEY (event_id),
  KEY idx_business_edge_events_device_time (device_entity_id, occurred_at),
  KEY idx_business_edge_events_received (received_at),
  CONSTRAINT fk_business_edge_events_device FOREIGN KEY (device_entity_id) REFERENCES entitiy_devices(device_entity_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS business_processing_jobs (
  job_id CHAR(36) NOT NULL,
  source_event_id CHAR(36) NOT NULL,
  device_entity_id CHAR(36) NOT NULL,
  status VARCHAR(32) NOT NULL,
  processor VARCHAR(128) NOT NULL,
  retry_count INT NOT NULL DEFAULT 0,
  started_at DATETIME(3) NULL,
  finished_at DATETIME(3) NULL,
  error_message TEXT NOT NULL,
  metadata JSON NOT NULL,
  created_at DATETIME(3) NOT NULL,
  updated_at DATETIME(3) NOT NULL,
  PRIMARY KEY (job_id),
  KEY idx_business_jobs_event (source_event_id),
  KEY idx_business_jobs_device_status (device_entity_id, status),
  KEY idx_business_jobs_status_time (status, created_at),
  CONSTRAINT fk_business_jobs_event FOREIGN KEY (source_event_id) REFERENCES business_edge_events(event_id),
  CONSTRAINT fk_business_jobs_device FOREIGN KEY (device_entity_id) REFERENCES entitiy_devices(device_entity_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS business_recognition_results (
  result_id CHAR(36) NOT NULL,
  source_event_id CHAR(36) NOT NULL,
  species_entity_id CHAR(36) NULL,
  species_name VARCHAR(128) NOT NULL,
  scientific_name VARCHAR(128) NOT NULL,
  confidence DECIMAL(5,4) NOT NULL,
  model_name VARCHAR(128) NOT NULL,
  model_version VARCHAR(64) NOT NULL,
  produced_by VARCHAR(32) NOT NULL,
  metadata JSON NOT NULL,
  created_at DATETIME(3) NOT NULL,
  updated_at DATETIME(3) NOT NULL,
  PRIMARY KEY (result_id),
  KEY idx_business_recognition_event (source_event_id),
  KEY idx_business_recognition_species (species_entity_id),
  CONSTRAINT fk_business_recognition_event FOREIGN KEY (source_event_id) REFERENCES business_edge_events(event_id),
  CONSTRAINT fk_business_recognition_species FOREIGN KEY (species_entity_id) REFERENCES entitiy_species_profiles(species_entity_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS business_monitoring_records (
  record_id CHAR(36) NOT NULL,
  device_entity_id CHAR(36) NOT NULL,
  source_event_id CHAR(36) NOT NULL,
  species_entity_id CHAR(36) NULL,
  captured_at DATETIME(3) NOT NULL,
  species_name VARCHAR(128) NOT NULL,
  scientific_name VARCHAR(128) NOT NULL,
  confidence DECIMAL(5,4) NOT NULL,
  temperature_c DECIMAL(6,2) NULL,
  humidity_pct INT NULL,
  media_refs JSON NOT NULL,
  processing_source VARCHAR(32) NOT NULL,
  model_version VARCHAR(64) NOT NULL,
  summary_text TEXT NOT NULL,
  species_intro TEXT NOT NULL,
  record_status VARCHAR(32) NOT NULL DEFAULT 'received',
  metadata JSON NOT NULL,
  created_at DATETIME(3) NOT NULL,
  updated_at DATETIME(3) NOT NULL,
  PRIMARY KEY (record_id),
  KEY idx_business_records_device_time (device_entity_id, captured_at),
  KEY idx_business_records_species_time (species_entity_id, captured_at),
  KEY idx_business_records_status_time (record_status, captured_at),
  CONSTRAINT fk_business_records_device FOREIGN KEY (device_entity_id) REFERENCES entitiy_devices(device_entity_id),
  CONSTRAINT fk_business_records_species FOREIGN KEY (species_entity_id) REFERENCES entitiy_species_profiles(species_entity_id),
  CONSTRAINT fk_business_records_event FOREIGN KEY (source_event_id) REFERENCES business_edge_events(event_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
