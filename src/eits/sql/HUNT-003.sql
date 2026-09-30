-- Broad key creation/use inventory; rows are leads, never alert verdicts.
WITH creations AS (
  SELECT *, json_extract_string(raw, '$.protoPayload.response.name') AS key_name
  FROM events WHERE provider='gcp' AND source='gcp.audit' AND service='iam.googleapis.com'
    AND action='google.iam.admin.v1.CreateServiceAccountKey' AND outcome IN ('success','unknown')
)
SELECT a.event_uid AS creation_uid, a.scope_type, a.scope_id, a.timestamp AS created_at,
       a.key_name, a.outcome AS creation_outcome,
       CASE WHEN a.key_name IS NULL OR a.timestamp IS NULL OR a.scope_id IS NULL
                 OR NOT regexp_full_match(a.key_name,'projects/[^/]+/serviceAccounts/[^/]+/keys/[^/]+')
            THEN 'unresolvable' WHEN count(b.event_uid)=0 THEN 'no_use_observed'
            ELSE 'use_observed' END AS observation,
       min(b.timestamp) AS first_use, max(b.timestamp) AS last_use,
       count(b.event_uid) AS event_count, count(DISTINCT b.service) AS distinct_services,
       count(DISTINCT b.action) AS distinct_actions,
       count(*) FILTER (WHERE b.outcome='failure') AS failures,
       coalesce(list(DISTINCT b.event_uid ORDER BY b.event_uid) FILTER (WHERE b.event_uid IS NOT NULL),[]) AS use_event_uids
FROM creations a LEFT JOIN events b ON a.scope_type=b.scope_type AND a.scope_id=b.scope_id
 AND regexp_full_match(a.key_name,'projects/[^/]+/serviceAccounts/[^/]+/keys/[^/]+')
 AND '//iam.googleapis.com/' || a.key_name=b.credential_id
 AND b.timestamp>=a.timestamp
 AND date_diff('microseconds',a.timestamp,b.timestamp)*1000
     + CAST(json_extract(b.extensions,'$.submicrosecond_nanos') AS BIGINT)
     - CAST(json_extract(a.extensions,'$.submicrosecond_nanos') AS BIGINT)>=0
 AND date_diff('microseconds',a.timestamp,b.timestamp)*1000
     + CAST(json_extract(b.extensions,'$.submicrosecond_nanos') AS BIGINT)
     - CAST(json_extract(a.extensions,'$.submicrosecond_nanos') AS BIGINT)<=? * 3600000000000
 AND a.event_uid<>b.event_uid
GROUP BY a.event_uid,a.scope_type,a.scope_id,a.timestamp,a.key_name,a.outcome
ORDER BY a.event_uid;
