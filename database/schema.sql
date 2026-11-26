-- TrustGuard Normalized MySQL 8+ Database Schema
-- Track 4: Trust, but verify (Yugaantar DevForge Hackathon)

CREATE DATABASE IF NOT EXISTS trustguard
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE trustguard;

CREATE TABLE IF NOT EXISTS users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) NOT NULL,
    display_name VARCHAR(120) NOT NULL,
    email VARCHAR(160) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(40) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    token_version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    CONSTRAINT uk_users_username UNIQUE (username),
    CONSTRAINT uk_users_email UNIQUE (email),
    INDEX idx_users_role (role)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS key_versions (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    key_alias VARCHAR(80) NOT NULL,
    version_number INT NOT NULL,
    algorithm VARCHAR(80) NOT NULL,
    status VARCHAR(32) NOT NULL,
    public_key_b64 TEXT NOT NULL,
    public_key_fingerprint VARCHAR(64) NOT NULL,
    key_reference VARCHAR(180) NOT NULL,
    grace_period_seconds INT NOT NULL DEFAULT 60,
    created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    distributed_at TIMESTAMP(3) NULL,
    committed_at TIMESTAMP(3) NULL,
    activation_time TIMESTAMP(3) NULL,
    grace_until TIMESTAMP(3) NULL,
    cutoff_time TIMESTAMP(3) NULL,
    failure_reason VARCHAR(255) NULL,
    CONSTRAINT uk_key_alias_version UNIQUE (key_alias, version_number),
    INDEX idx_key_versions_status (status)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS devices (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    device_uid VARCHAR(64) NOT NULL,
    owner_user_id BIGINT NOT NULL,
    device_name VARCHAR(120) NOT NULL,
    public_key_b64 TEXT NOT NULL,
    public_key_fingerprint VARCHAR(64) NOT NULL,
    key_reference VARCHAR(180) NOT NULL,
    key_algorithm VARCHAR(80) NOT NULL,
    signing_public_key_b64 TEXT NOT NULL,
    status VARCHAR(32) NOT NULL,
    enrolled_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    last_seen_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    revoked_at TIMESTAMP(3) NULL,
    replaced_by_device_id BIGINT NULL,
    CONSTRAINT uk_devices_uid UNIQUE (device_uid),
    CONSTRAINT fk_devices_owner FOREIGN KEY (owner_user_id) REFERENCES users (id),
    CONSTRAINT fk_devices_replaced_by FOREIGN KEY (replaced_by_device_id) REFERENCES devices (id),
    INDEX idx_devices_owner_status (owner_user_id, status),
    INDEX idx_devices_fingerprint (public_key_fingerprint)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS resources (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    resource_key VARCHAR(80) NOT NULL,
    title VARCHAR(160) NOT NULL,
    owner_user_id BIGINT NOT NULL,
    allowed_services VARCHAR(255) NOT NULL,
    classification VARCHAR(40) NOT NULL,
    content_ciphertext_b64 TEXT NOT NULL,
    content_iv_b64 VARCHAR(64) NOT NULL,
    content_aad VARCHAR(255) NOT NULL,
    active_key_version_id BIGINT NOT NULL,
    created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    CONSTRAINT uk_resources_key UNIQUE (resource_key),
    CONSTRAINT fk_resources_owner FOREIGN KEY (owner_user_id) REFERENCES users (id),
    CONSTRAINT fk_resources_key_ver FOREIGN KEY (active_key_version_id) REFERENCES key_versions (id),
    INDEX idx_resources_owner (owner_user_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS role_permissions (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    role_name VARCHAR(40) NOT NULL,
    service_name VARCHAR(64) NOT NULL,
    target_service VARCHAR(64) NOT NULL,
    action VARCHAR(40) NOT NULL,
    allowed BOOLEAN NOT NULL DEFAULT TRUE,
    description VARCHAR(255) NULL,
    CONSTRAINT uk_role_perm_tuple UNIQUE (role_name, service_name, target_service, action),
    INDEX idx_role_perm_lookup (role_name, target_service, action)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS access_events (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    request_id VARCHAR(96) NOT NULL,
    actor_username VARCHAR(64) NOT NULL,
    authenticated_principal VARCHAR(64) NOT NULL,
    simulation_mode BOOLEAN NOT NULL DEFAULT FALSE,
    device_id BIGINT NULL,
    source_service VARCHAR(64) NOT NULL,
    target_service VARCHAR(64) NOT NULL,
    resource_key VARCHAR(80) NOT NULL,
    action VARCHAR(40) NOT NULL,
    decision VARCHAR(16) NOT NULL,
    decision_reason VARCHAR(255) NOT NULL,
    key_version_used INT NOT NULL,
    node_code VARCHAR(64) NULL,
    timestamp_utc TIMESTAMP(3) NOT NULL,
    created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    CONSTRAINT uk_access_events_request_id UNIQUE (request_id),
    CONSTRAINT fk_access_events_device FOREIGN KEY (device_id) REFERENCES devices (id),
    INDEX idx_access_events_actor_ts (actor_username, timestamp_utc),
    INDEX idx_access_events_decision (decision)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS simulated_nodes (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    node_code VARCHAR(64) NOT NULL,
    node_name VARCHAR(120) NOT NULL,
    region VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL,
    current_key_version INT NOT NULL,
    current_revocation_version BIGINT NOT NULL DEFAULT 0,
    last_heartbeat_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    last_revocation_enforced_at TIMESTAMP(3) NULL,
    last_propagation_ms BIGINT NULL,
    simulate_ack_failure BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT uk_simulated_nodes_code UNIQUE (node_code)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS node_key_acknowledgements (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    key_version_id BIGINT NOT NULL,
    node_id BIGINT NOT NULL,
    ack_status VARCHAR(32) NOT NULL,
    acknowledged_at TIMESTAMP(3) NULL,
    detail_message VARCHAR(255) NULL,
    CONSTRAINT uk_node_key_ack UNIQUE (key_version_id, node_id),
    CONSTRAINT fk_nka_key_version FOREIGN KEY (key_version_id) REFERENCES key_versions (id),
    CONSTRAINT fk_nka_node FOREIGN KEY (node_id) REFERENCES simulated_nodes (id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS revocations (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    revocation_version BIGINT NOT NULL,
    target_type VARCHAR(32) NOT NULL,
    device_id BIGINT NULL,
    username VARCHAR(64) NOT NULL,
    reason VARCHAR(255) NOT NULL,
    initiated_by VARCHAR(64) NOT NULL,
    revoked_at TIMESTAMP(3) NOT NULL,
    propagation_completed_at TIMESTAMP(3) NOT NULL,
    propagation_latency_ms BIGINT NOT NULL,
    nodes_enforced_count INT NOT NULL,
    total_nodes_count INT NOT NULL,
    CONSTRAINT uk_revocations_version UNIQUE (revocation_version),
    CONSTRAINT fk_revocations_device FOREIGN KEY (device_id) REFERENCES devices (id),
    INDEX idx_revocations_username (username)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    event_id VARCHAR(96) NOT NULL,
    seq_number BIGINT NOT NULL,
    actor VARCHAR(64) NOT NULL,
    action VARCHAR(80) NOT NULL,
    resource VARCHAR(128) NOT NULL,
    detail VARCHAR(512) NOT NULL,
    event_timestamp_utc TIMESTAMP(3) NOT NULL,
    prev_hash VARCHAR(64) NOT NULL,
    current_hash VARCHAR(64) NOT NULL,
    created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    CONSTRAINT uk_audit_logs_event_id UNIQUE (event_id),
    CONSTRAINT uk_audit_logs_seq UNIQUE (seq_number),
    INDEX idx_audit_logs_actor (actor),
    INDEX idx_audit_logs_ts (event_timestamp_utc)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS security_alerts (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    alert_uid VARCHAR(96) NOT NULL,
    rule_name VARCHAR(80) NOT NULL,
    severity VARCHAR(24) NOT NULL,
    outcome_classification VARCHAR(32) NOT NULL,
    actor VARCHAR(64) NOT NULL,
    service_path VARCHAR(255) NOT NULL,
    event_ids_json TEXT NOT NULL,
    correlation_id VARCHAR(64) NULL,
    session_id VARCHAR(64) NULL,
    source_event_time_utc TIMESTAMP(3) NULL,
    detected_at TIMESTAMP(3) NOT NULL,
    detection_latency_ms BIGINT NOT NULL DEFAULT 0,
    explanation TEXT NOT NULL,
    dataset_source VARCHAR(64) NOT NULL DEFAULT 'LIVE_RUNTIME',
    resolved BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT uk_security_alerts_uid UNIQUE (alert_uid),
    INDEX idx_security_alerts_severity (severity),
    INDEX idx_security_alerts_actor (actor),
    INDEX idx_security_alerts_rule (rule_name)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS secure_messages (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    message_id VARCHAR(96) NOT NULL,
    sender_username VARCHAR(64) NOT NULL,
    sender_device_id BIGINT NOT NULL,
    recipient_username VARCHAR(64) NOT NULL,
    recipient_device_id BIGINT NOT NULL,
    algorithm VARCHAR(80) NOT NULL,
    signature_algorithm VARCHAR(40) NOT NULL,
    kem_ciphertext_b64 TEXT NOT NULL,
    iv_b64 VARCHAR(64) NOT NULL,
    ciphertext_b64 TEXT NOT NULL,
    aad_json TEXT NOT NULL,
    signature_b64 TEXT NOT NULL,
    ephemeral_key_id VARCHAR(96) NOT NULL,
    forward_secrecy_erased BOOLEAN NOT NULL DEFAULT TRUE,
    status VARCHAR(32) NOT NULL,
    verification_outcome VARCHAR(80) NOT NULL,
    created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    delivered_at TIMESTAMP(3) NULL,
    CONSTRAINT uk_secure_messages_msg_id UNIQUE (message_id),
    CONSTRAINT fk_sm_sender_device FOREIGN KEY (sender_device_id) REFERENCES devices (id),
    CONSTRAINT fk_sm_recipient_device FOREIGN KEY (recipient_device_id) REFERENCES devices (id),
    INDEX idx_secure_messages_recipient (recipient_username, status)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS consumed_messages (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    message_id VARCHAR(96) NOT NULL,
    recipient_username VARCHAR(64) NOT NULL,
    sender_username VARCHAR(64) NOT NULL,
    aad_hash VARCHAR(64) NOT NULL,
    consumed_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    CONSTRAINT uk_consumed_messages_msg_id UNIQUE (message_id),
    INDEX idx_consumed_messages_recipient (recipient_username)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS backup_records (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    backup_id VARCHAR(80) NOT NULL,
    created_by VARCHAR(64) NOT NULL,
    key_version_number INT NOT NULL,
    revocation_version BIGINT NOT NULL,
    checksum_sha256 VARCHAR(64) NOT NULL,
    hmac_sha256 VARCHAR(64) NULL,
    verification_status VARCHAR(32) NOT NULL,
    restore_status VARCHAR(32) NOT NULL,
    item_count INT NOT NULL,
    payload_snapshot_json LONGTEXT NOT NULL,
    created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    verified_at TIMESTAMP(3) NULL,
    restored_at TIMESTAMP(3) NULL,
    CONSTRAINT uk_backup_records_id UNIQUE (backup_id),
    INDEX idx_backup_records_created (created_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS backup_items (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    backup_record_id BIGINT NOT NULL,
    item_type VARCHAR(40) NOT NULL,
    item_key VARCHAR(96) NOT NULL,
    item_checksum_sha256 VARCHAR(64) NOT NULL,
    serialized_data_json TEXT NOT NULL,
    CONSTRAINT fk_backup_items_record FOREIGN KEY (backup_record_id) REFERENCES backup_records (id) ON DELETE CASCADE,
    INDEX idx_backup_items_record (backup_record_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS session_records (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    session_id VARCHAR(80) NOT NULL,
    actor_username VARCHAR(64) NOT NULL,
    device_id BIGINT NULL,
    peer_device_id BIGINT NULL,
    status VARCHAR(32) NOT NULL,
    auth_token_hash VARCHAR(64) NOT NULL,
    created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    last_active_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    expires_at TIMESTAMP(3) NOT NULL,
    resumed_count INT NOT NULL DEFAULT 0,
    CONSTRAINT uk_session_records_sid UNIQUE (session_id),
    CONSTRAINT fk_session_device FOREIGN KEY (device_id) REFERENCES devices (id),
    CONSTRAINT fk_session_peer_device FOREIGN KEY (peer_device_id) REFERENCES devices (id),
    INDEX idx_session_actor_status (actor_username, status)
) ENGINE=InnoDB;
