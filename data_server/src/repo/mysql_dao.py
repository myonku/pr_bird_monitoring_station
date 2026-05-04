from .mysql_client import MySQLBaseDAO, MySQLClient


class AuthTokenRecordsDAO(MySQLBaseDAO):
    def __init__(self, mysql_db: MySQLClient):
        super().__init__(
            mysql_db=mysql_db,
            table_name="auth_token_records",
            primary_key="id",
            allowed_columns={
                "id",
                "raw_token",
                "family_id",
                "session_id",
                "token_type",
                "status",
                "storage",
                "principal_type",
                "principal_id",
                "parent_token_id",
                "client_id",
                "gateway_id",
                "role_snapshot",
                "scope_snapshot",
                "issued_at",
                "expires_at",
                "last_validated_at",
                "revoked_at",
            },
        )


class AuthTokenClaimsDAO(MySQLBaseDAO):
    def __init__(self, mysql_db: MySQLClient):
        super().__init__(
            mysql_db=mysql_db,
            table_name="auth_token_claims",
            primary_key="token_id",
            allowed_columns={
                "token_id",
                "issuer",
                "audience",
                "subject",
                "token_type",
                "entity_type",
                "entity_id",
                "principal_id",
                "session_id",
                "family_id",
                "parent_id",
                "role",
                "scopes",
                "auth_method",
                "client_id",
                "gateway_id",
                "source_service",
                "target_service",
                "issued_at",
                "expires_at",
            },
        )


class ServicePublicKeysDAO(MySQLBaseDAO):
    def __init__(self, mysql_db: MySQLClient):
        super().__init__(
            mysql_db=mysql_db,
            table_name="auth_entity_public_keys",
            primary_key="key_id",
            allowed_columns={
                "key_id",
                "entity_type",
                "entity_id",
                "entity_name",
                "instance_id",
                "instance_name",
                "public_key_pem",
                "fingerprint",
                "status",
                "created_at",
                "activated_at",
                "expires_at",
                "revoked_at",
            },
        )


class EntitySpeciesProfilesDAO(MySQLBaseDAO):
    def __init__(self, mysql_db: MySQLClient):
        super().__init__(
            mysql_db=mysql_db,
            table_name="entitiy_species_profiles",
            primary_key="species_entity_id",
            allowed_columns={
                "species_entity_id",
                "species_name",
                "scientific_name",
                "label_name",
                "alias_names",
                "metadata",
                "created_at",
                "updated_at",
            },
        )


class EntityDevicesDAO(MySQLBaseDAO):
    def __init__(self, mysql_db: MySQLClient):
        super().__init__(
            mysql_db=mysql_db,
            table_name="entitiy_devices",
            primary_key="device_entity_id",
            allowed_columns={
                "device_entity_id",
                "device_name",
                "location_name",
                "latitude",
                "longitude",
                "last_heartbeat_at",
                "status",
                "active_comm_key_id",
                "created_at",
                "updated_at",
                "metadata",
            },
        )


class EntityUsersDAO(MySQLBaseDAO):
    def __init__(self, mysql_db: MySQLClient):
        super().__init__(
            mysql_db=mysql_db,
            table_name="entitiy_users",
            primary_key="user_entity_id",
            allowed_columns={
                "user_entity_id",
                "user_profile_id",
                "user_name",
                "email",
                "phone",
                "role",
                "password_hash",
                "hash_algorithm",
                "status",
                "created_at",
                "updated_at",
                "last_login_at",
                "password_updated_at",
                "metadata",
            },
        )
