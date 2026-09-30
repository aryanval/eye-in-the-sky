-- All new credentials, including unused keys and creations whose issued key ID is missing.
-- No alert threshold; counts describe ONLY the supplied observation window.
WITH creations AS (
  SELECT *, json_extract_string(raw, '$.responseElements.accessKey.accessKeyId') AS issued_key_id
  FROM events WHERE provider='aws' AND service='iam.amazonaws.com'
    AND action='CreateAccessKey' AND outcome='success'
)
SELECT a.event_uid AS creation_uid, a.source_event_id AS creation_event_id,
       a.account_id, a.timestamp AS created_at, a.actor_arn AS creator, a.issued_key_id,
       CASE WHEN a.issued_key_id IS NULL OR a.timestamp IS NULL OR a.account_id IS NULL
            THEN 'unresolvable' WHEN count(b.event_uid)=0 THEN 'no_use_observed'
            ELSE 'use_observed' END AS observation,
       min(b.timestamp) AS first_use, max(b.timestamp) AS last_use,
       count(b.event_uid) AS event_count,
       count(DISTINCT b.service) AS distinct_services,
       count(DISTINCT b.action) AS distinct_actions,
       count(DISTINCT b.source_ip) AS distinct_source_ips,
       count(*) FILTER (WHERE b.outcome='failure') AS failures,
       count(*) FILTER (WHERE b.action IN ('AttachUserPolicy', 'AttachRolePolicy', 'StopLogging',
                                           'AuthorizeSecurityGroupIngress')) AS sensitive_actions,
       coalesce(list(DISTINCT b.source_event_id ORDER BY b.source_event_id)
                FILTER (WHERE b.event_uid IS NOT NULL), []) AS use_event_ids,
       coalesce(list(DISTINCT b.event_uid ORDER BY b.event_uid)
                FILTER (WHERE b.event_uid IS NOT NULL), []) AS use_event_uids
FROM creations a LEFT JOIN events b
  ON a.account_id=b.account_id AND a.issued_key_id=b.credential_id
 AND b.timestamp >= a.timestamp AND b.timestamp <= a.timestamp + (? * INTERVAL '1 hour')
 AND a.event_uid <> b.event_uid
GROUP BY a.event_uid, a.source_event_id, a.account_id, a.timestamp, a.actor_arn, a.issued_key_id
ORDER BY sensitive_actions DESC, failures DESC, a.event_uid;
