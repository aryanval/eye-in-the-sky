-- Azure REST Activity: same explicit resource scope and actor namespace, ordered operations.
-- A successful role assignment does not by itself establish a privileged role.
SELECT a.event_uid AS start_uid, b.event_uid AS end_uid,
       a.source_event_id AS start_event_id, b.source_event_id AS end_event_id,
       a.timestamp AS started_at, b.timestamp AS ended_at,
       epoch(b.timestamp - a.timestamp) +
           (cast(json_extract_string(b.extensions, '$.timestamp_submicrosecond_ns') AS INTEGER) -
            cast(json_extract_string(a.extensions, '$.timestamp_submicrosecond_ns') AS INTEGER)) / 1000000000.0
           AS elapsed_seconds,
       a.scope_type, a.scope_id, a.tenant_id, a.actor_id,
       json_extract_string(a.extensions, '$.actor_tenant_id') AS actor_tenant_id,
       json_extract_string(a.raw, '$.resourceId') AS diagnostic_setting,
       json_extract_string(b.raw, '$.resourceId') AS role_assignment,
       a.action AS logging_action, b.action AS access_action
FROM events a JOIN events b
  ON a.scope_type = b.scope_type AND a.scope_id = b.scope_id
 AND a.tenant_id = b.tenant_id AND a.actor_id = b.actor_id
 AND json_extract_string(a.extensions, '$.actor_tenant_id') =
     json_extract_string(b.extensions, '$.actor_tenant_id')
 AND (b.timestamp > a.timestamp OR
      (b.timestamp = a.timestamp AND
       cast(json_extract_string(b.extensions, '$.timestamp_submicrosecond_ns') AS INTEGER) >
       cast(json_extract_string(a.extensions, '$.timestamp_submicrosecond_ns') AS INTEGER)))
 AND (b.timestamp < a.timestamp + INTERVAL '30 minutes' OR
      (b.timestamp = a.timestamp + INTERVAL '30 minutes' AND
       cast(json_extract_string(b.extensions, '$.timestamp_submicrosecond_ns') AS INTEGER) <=
       cast(json_extract_string(a.extensions, '$.timestamp_submicrosecond_ns') AS INTEGER)))
WHERE a.provider = 'azure' AND b.provider = 'azure'
  AND a.source = 'azure.activity' AND b.source = 'azure.activity'
  AND a.scope_type = 'azure.subscription'
  AND lower(a.action) = 'microsoft.insights/diagnosticsettings/delete'
  AND lower(b.action) = 'microsoft.authorization/roleassignments/write'
  AND a.outcome = 'success' AND b.outcome = 'success'
ORDER BY a.event_uid, b.event_uid;
