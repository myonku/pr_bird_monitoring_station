-- 实体域表结构（MySQL 8.0+）

-- 实体域：设备/物种/后端服务扩展表

CREATE TABLE IF NOT EXISTS entitiy_users (
  user_entity_id CHAR(36) NOT NULL,
  user_profile_id CHAR(36) NOT NULL,
  user_name VARCHAR(128) NOT NULL,
  role VARCHAR(32) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  hash_algorithm VARCHAR(64) NOT NULL,
  email VARCHAR(128) NULL,
  phone VARCHAR(32) NULL,
  status VARCHAR(32) NOT NULL,
  created_at DATETIME(3) NOT NULL,
  updated_at DATETIME(3) NOT NULL,
  last_login_at DATETIME(3) NULL,
  password_updated_at DATETIME(3) NOT NULL,
  metadata JSON NOT NULL,
  PRIMARY KEY (user_entity_id),
  UNIQUE KEY uk_entitiy_users_profile_id (user_profile_id),
  UNIQUE KEY uk_entitiy_users_name (user_name),
  UNIQUE KEY uk_entitiy_users_email (email),
  UNIQUE KEY uk_entitiy_users_phone (phone),
  KEY idx_entitiy_users_role_status (role, status),
  KEY idx_entitiy_users_status_updated (status, updated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS entitiy_devices (
  device_entity_id CHAR(36) NOT NULL,
  device_name VARCHAR(128) NOT NULL,
  location_name VARCHAR(128) NOT NULL,
  latitude DECIMAL(10,7) NOT NULL,
  longitude DECIMAL(10,7) NOT NULL,
  last_heartbeat_at DATETIME(3) NOT NULL,
  status VARCHAR(32) NOT NULL,
  active_comm_key_id CHAR(36) NOT NULL,
  created_at DATETIME(3) NOT NULL,
  updated_at DATETIME(3) NOT NULL,
  metadata JSON NOT NULL,
  PRIMARY KEY (device_entity_id),
  KEY idx_entitiy_devices_name (device_name),
  KEY idx_entitiy_devices_status (status),
  KEY idx_entitiy_devices_heartbeat (last_heartbeat_at),
  KEY idx_entitiy_devices_comm_key (active_comm_key_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS entitiy_services (
  service_entity_id CHAR(36) NOT NULL,
  service_name VARCHAR(128) NOT NULL,
  service_type VARCHAR(64) NOT NULL,
  endpoint VARCHAR(255) NOT NULL,
  active_comm_key_id CHAR(36) NOT NULL,
  last_heartbeat_at DATETIME(3) NOT NULL,
  created_at DATETIME(3) NOT NULL,
  updated_at DATETIME(3) NOT NULL,
  metadata JSON NOT NULL,
  PRIMARY KEY (service_entity_id),
  KEY idx_entitiy_services_name (service_name),
  KEY idx_entitiy_services_type (service_type),
  KEY idx_entitiy_services_heartbeat (last_heartbeat_at),
  KEY idx_entitiy_services_comm_key (active_comm_key_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


CREATE TABLE IF NOT EXISTS entitiy_species_profiles (
  species_entity_id CHAR(36) NOT NULL,
  species_name VARCHAR(128) NOT NULL,
  scientific_name VARCHAR(128) NOT NULL,
  alias_names JSON NOT NULL,
  metadata JSON NOT NULL,
  created_at DATETIME(3) NOT NULL,
  updated_at DATETIME(3) NOT NULL,
  PRIMARY KEY (species_entity_id),
  UNIQUE KEY uk_entitiy_species_name (species_name),
  UNIQUE KEY uk_entitiy_scientific_name (scientific_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;