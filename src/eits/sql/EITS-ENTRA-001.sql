-- Named administrative operations with exact user and mentioned target IDs.
-- App-role direction, role sensitivity, credential use and authorization are unresolved.
WITH targets AS (
  SELECT e.*, json_extract_string(t.value, '$.id') AS target_id,
         cast(json_extract_string(e.extensions, '$.timestamp_submicrosecond_ns') AS INTEGER) AS submicrosecond_ns
  FROM events e, json_each(e.raw, '$.targetResources') t
  WHERE e.provider='azure' AND e.source='azure.entra.audit'
    AND e.scope_type='azure.tenant' AND e.scope_id IS NOT NULL
    AND e.actor_type='User' AND e.actor_id IS NOT NULL
    AND e.outcome='success'
    AND json_extract_string(e.raw, '$.category')='ApplicationManagement'
    AND json_extract_string(t.value, '$.type')='ServicePrincipal'
    AND json_type(t.value, '$.id')='VARCHAR'
    AND nullif(json_extract_string(t.value, '$.id'), '') IS NOT NULL
)
SELECT DISTINCT a.event_uid AS credential_uid, b.event_uid AS assignment_uid,
       a.source_event_id AS credential_event_id, b.source_event_id AS assignment_event_id,
       a.scope_type, a.scope_id, a.tenant_id, a.actor_id AS initiating_user_id,
       a.target_id AS mentioned_service_principal_id,
       a.timestamp AS credential_added_at, b.timestamp AS role_assigned_at,
       epoch(b.timestamp-a.timestamp) +
           (b.submicrosecond_ns-a.submicrosecond_ns)/1000000000.0 AS elapsed_seconds
FROM targets a JOIN targets b
  ON a.scope_id=b.scope_id AND a.tenant_id=b.tenant_id
 AND a.actor_id=b.actor_id AND a.target_id=b.target_id
 AND (b.timestamp>a.timestamp OR
      (b.timestamp=a.timestamp AND b.submicrosecond_ns>a.submicrosecond_ns))
 AND (b.timestamp<a.timestamp+INTERVAL '30 minutes' OR
      (b.timestamp=a.timestamp+INTERVAL '30 minutes'
       AND b.submicrosecond_ns<=a.submicrosecond_ns))
WHERE a.action='Add service principal credentials'
  AND b.action='Add app role assignment to service principal'
ORDER BY credential_uid, assignment_uid, mentioned_service_principal_id;
