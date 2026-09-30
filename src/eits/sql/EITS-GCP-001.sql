-- Exact key-resource attribution; no email, IP, alias or cross-project join.
SELECT a.event_uid AS creation_uid, b.event_uid AS policy_uid,
       a.scope_type, a.scope_id, a.timestamp AS created_at, b.timestamp AS policy_at,
       (date_diff('microseconds',a.timestamp,b.timestamp)*1000
        + CAST(json_extract(b.extensions,'$.submicrosecond_nanos') AS BIGINT)
        - CAST(json_extract(a.extensions,'$.submicrosecond_nanos') AS BIGINT))/1000000000.0 AS elapsed_seconds,
       json_extract_string(a.raw, '$.protoPayload.response.name') AS created_key_name,
       b.credential_id AS used_key_name,
       json_extract_string(b.raw, '$.protoPayload.resourceName') AS policy_resource,
       a.actor_id AS creator, b.actor_id AS policy_actor
FROM events a JOIN events b
  ON a.scope_type=b.scope_type AND a.scope_id=b.scope_id
 AND '//iam.googleapis.com/' || json_extract_string(a.raw, '$.protoPayload.response.name')=b.credential_id
 AND b.timestamp>=a.timestamp AND b.timestamp<=a.timestamp+INTERVAL '30 minutes'
 AND date_diff('microseconds',a.timestamp,b.timestamp)*1000
     + CAST(json_extract(b.extensions,'$.submicrosecond_nanos') AS BIGINT)
     - CAST(json_extract(a.extensions,'$.submicrosecond_nanos') AS BIGINT)>0
 AND date_diff('microseconds',a.timestamp,b.timestamp)*1000
     + CAST(json_extract(b.extensions,'$.submicrosecond_nanos') AS BIGINT)
     - CAST(json_extract(a.extensions,'$.submicrosecond_nanos') AS BIGINT)<=1800000000000
WHERE a.provider='gcp' AND b.provider='gcp' AND a.source='gcp.audit' AND b.source='gcp.audit'
  AND a.scope_type='gcp.project'
  AND a.service='iam.googleapis.com' AND a.action='google.iam.admin.v1.CreateServiceAccountKey'
  AND a.outcome='success'
  AND regexp_full_match(json_extract_string(a.raw, '$.protoPayload.response.name'), 'projects/[^/]+/serviceAccounts/[^/]+/keys/[^/]+')
  AND b.service='cloudresourcemanager.googleapis.com' AND b.action='SetIamPolicy'
  AND b.outcome='success'
ORDER BY a.event_uid,b.event_uid;
