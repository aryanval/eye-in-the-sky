-- Successful key creation followed by use of THAT credential for an admin policy attachment.
-- No scenario IDs, ground truth labels, allowlists, or IP-based identity guesses.
SELECT a.event_uid AS start_uid, b.event_uid AS end_uid,
       a.source_event_id AS start_event_id, b.source_event_id AS end_event_id,
       a.timestamp AS started_at, b.timestamp AS ended_at,
       epoch(b.timestamp - a.timestamp) AS elapsed_seconds,
       a.account_id,
       json_extract_string(a.raw, '$.responseElements.accessKey.accessKeyId') AS created_key_id,
       a.actor_arn AS key_creator,
       json_extract_string(a.raw, '$.responseElements.accessKey.userName') AS key_owner,
       b.actor_arn AS policy_actor,
       b.action AS policy_action,
       coalesce(json_extract_string(b.raw, '$.requestParameters.userName'),
                json_extract_string(b.raw, '$.requestParameters.roleName')) AS policy_target,
       json_extract_string(b.raw, '$.requestParameters.policyArn') AS policy_arn
FROM events a JOIN events b
  ON a.account_id = b.account_id
 AND json_extract_string(a.raw, '$.responseElements.accessKey.accessKeyId') = b.credential_id
 AND b.timestamp > a.timestamp
 AND b.timestamp <= a.timestamp + INTERVAL '30 minutes'
WHERE a.provider = 'aws' AND b.provider = 'aws'
  AND a.service = 'iam.amazonaws.com' AND a.action = 'CreateAccessKey' AND a.outcome = 'success'
  AND b.service = 'iam.amazonaws.com' AND b.action IN ('AttachUserPolicy', 'AttachRolePolicy')
  AND b.outcome = 'success'
  AND json_extract_string(b.raw, '$.requestParameters.policyArn') = 'arn:aws:iam::aws:policy/AdministratorAccess'
ORDER BY a.event_uid, b.event_uid;
