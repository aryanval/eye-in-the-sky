-- Expand each permission independently; public CIDR and admin port must coexist in that entry.
WITH permissions AS (
    SELECT e.*, p.key AS permission_index, p.value AS permission
    FROM events e, json_each(e.raw, '$.requestParameters.ipPermissions.items') p
    WHERE e.provider = 'aws' AND e.service = 'ec2.amazonaws.com'
      AND e.action = 'AuthorizeSecurityGroupIngress' AND e.outcome = 'success'
), public_ranges AS (
    SELECT p.*, json_extract_string(r.value, '$.cidrIp') AS cidr
    FROM permissions p, json_each(p.permission, '$.ipRanges.items') r
    WHERE json_extract_string(r.value, '$.cidrIp') = '0.0.0.0/0'
    UNION ALL
    SELECT p.*, json_extract_string(r.value, '$.cidrIpv6') AS cidr
    FROM permissions p, json_each(p.permission, '$.ipv6Ranges.items') r
    WHERE json_extract_string(r.value, '$.cidrIpv6') = '::/0'
)
SELECT a.event_uid AS start_uid, b.event_uid AS end_uid,
       a.source_event_id AS start_event_id, b.source_event_id AS end_event_id,
       a.timestamp AS started_at, b.timestamp AS ended_at,
       epoch(b.timestamp - a.timestamp) AS elapsed_seconds,
       a.account_id, a.actor_id, a.credential_id,
       json_extract_string(a.raw, '$.requestParameters.name') AS trail,
       json_extract_string(b.raw, '$.requestParameters.groupId') AS security_group,
       b.permission_index, b.cidr,
       json_extract_string(b.permission, '$.ipProtocol') AS protocol,
       try_cast(json_extract_string(b.permission, '$.fromPort') AS INTEGER) AS from_port,
       try_cast(json_extract_string(b.permission, '$.toPort') AS INTEGER) AS to_port
FROM events a JOIN public_ranges b
  ON a.account_id = b.account_id AND a.actor_id = b.actor_id AND a.credential_id = b.credential_id
 AND b.timestamp > a.timestamp AND b.timestamp <= a.timestamp + INTERVAL '30 minutes'
WHERE a.provider = 'aws' AND a.service = 'cloudtrail.amazonaws.com'
  AND a.action = 'StopLogging' AND a.outcome = 'success'
  AND (
    json_extract_string(b.permission, '$.ipProtocol') = '-1'
    OR (json_extract_string(b.permission, '$.ipProtocol') IN ('tcp', '6') AND (
      22 BETWEEN try_cast(json_extract_string(b.permission, '$.fromPort') AS INTEGER)
             AND try_cast(json_extract_string(b.permission, '$.toPort') AS INTEGER)
      OR 3389 BETWEEN try_cast(json_extract_string(b.permission, '$.fromPort') AS INTEGER)
             AND try_cast(json_extract_string(b.permission, '$.toPort') AS INTEGER)
    ))
  )
ORDER BY a.event_uid, b.event_uid, b.permission_index, b.cidr;
