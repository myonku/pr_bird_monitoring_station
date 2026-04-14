-- 实体域表结构（MySQL 8.0+）

-- 实体域：站点/物种/后端服务扩展表


CREATE TABLE IF NOT EXISTS entitiy_user (
    
)

CREATE TABLE IF NOT EXISTS entitiy_device (
    
)


CREATE TABLE IF NOT EXISTS entitiy_service (
    
)


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