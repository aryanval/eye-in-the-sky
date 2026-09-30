CREATE TABLE IF NOT EXISTS metadata (key VARCHAR PRIMARY KEY, value VARCHAR NOT NULL);
INSERT INTO metadata VALUES ('schema_version', '1') ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS datasets (
    dataset_id VARCHAR PRIMARY KEY, manifest JSON NOT NULL, manifest_sha256 VARCHAR NOT NULL
);
CREATE TABLE IF NOT EXISTS artifacts (sha256 VARCHAR PRIMARY KEY, content BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS events (
    event_uid VARCHAR PRIMARY KEY, source_event_id VARCHAR, timestamp TIMESTAMPTZ,
    provider VARCHAR NOT NULL, source VARCHAR NOT NULL, account_id VARCHAR, region VARCHAR,
    actor_id VARCHAR, actor_type VARCHAR, actor_arn VARCHAR, credential_id VARCHAR,
    source_address VARCHAR, source_ip VARCHAR, service VARCHAR NOT NULL, action VARCHAR NOT NULL,
    outcome VARCHAR NOT NULL, error_code VARCHAR, resources JSON NOT NULL,
    authentication JSON NOT NULL, privilege_context JSON NOT NULL, extensions JSON NOT NULL,
    raw JSON NOT NULL, quality JSON NOT NULL
);
CREATE TABLE IF NOT EXISTS occurrences (
    dataset_id VARCHAR NOT NULL, artifact_sha256 VARCHAR NOT NULL, source_path VARCHAR NOT NULL,
    record_pointer VARCHAR NOT NULL, event_uid VARCHAR NOT NULL,
    PRIMARY KEY (dataset_id, source_path, record_pointer)
);
