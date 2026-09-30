-- All predicates must describe the same BindingDelta; a returned policy is not a delta.
SELECT e.event_uid AS policy_uid, e.scope_type, e.scope_id, e.timestamp,
       json_extract_string(e.raw, '$.protoPayload.resourceName') AS bucket_resource,
       json_extract_string(d.value, '$.member') AS member,
       json_extract_string(d.value, '$.role') AS role,
       d.key AS delta_index, e.actor_id
FROM events e, json_each(e.raw, '$.protoPayload.serviceData.policyDelta.bindingDeltas') d
WHERE e.provider='gcp' AND e.source='gcp.audit' AND e.scope_type='gcp.project' AND e.scope_id IS NOT NULL
  AND e.service='storage.googleapis.com' AND e.action='storage.setIamPermissions'
  AND e.outcome='success'
  AND json_extract_string(e.raw, '$.resource.type')='gcs_bucket'
  AND json_extract_string(e.raw, '$.protoPayload.resourceName') IS NOT NULL
  AND json_extract_string(e.raw, '$.protoPayload.resourceName')<>''
  AND json_extract_string(e.raw, '$.protoPayload.serviceData."@type"')='type.googleapis.com/google.iam.v1.logging.AuditData'
  AND json_extract_string(d.value, '$.action')='ADD'
  AND json_extract_string(d.value, '$.member') IN ('allUsers','allAuthenticatedUsers')
  AND json_extract_string(d.value, '$.role') IN ('roles/storage.objectViewer','roles/storage.objectAdmin','roles/storage.admin')
ORDER BY e.event_uid,d.key;
