-- Additive migration. Existing identities, raw evidence, artifacts, and datasets are unchanged.
ALTER TABLE events ADD COLUMN scope_type VARCHAR;
ALTER TABLE events ADD COLUMN scope_id VARCHAR;
ALTER TABLE events ADD COLUMN tenant_id VARCHAR;
UPDATE events SET scope_type='aws.account', scope_id=account_id
    WHERE provider='aws' AND source='aws.cloudtrail';
UPDATE metadata SET value='2' WHERE key='schema_version';
