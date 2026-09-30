-- Exploratory sign-in inventory within hours of each tenant/user's first retained sign-in.
-- Unknown identities stay separate per event; no threshold or maliciousness verdict.
WITH parameters AS (SELECT ? * INTERVAL '1 hour' AS horizon), source_records AS (
  SELECT *, cast(json_extract_string(extensions, '$.timestamp_submicrosecond_ns') AS INTEGER)
         AS submicrosecond_ns
  FROM events WHERE provider='azure' AND source='azure.entra.signin'
), anchored AS (
  SELECT *, first_value(timestamp) OVER observation AS window_start,
         first_value(submicrosecond_ns) OVER observation AS window_start_ns
  FROM source_records
  WINDOW observation AS (
    PARTITION BY scope_type, scope_id, tenant_id, actor_id,
    CASE WHEN scope_id IS NULL OR actor_id IS NULL THEN event_uid END
    ORDER BY timestamp NULLS LAST, submicrosecond_ns, event_uid
  )
), selected AS (
  SELECT * FROM anchored
  WHERE timestamp IS NULL OR timestamp<window_start+(SELECT horizon FROM parameters)
     OR (timestamp=window_start+(SELECT horizon FROM parameters) AND submicrosecond_ns<=window_start_ns)
)
SELECT scope_type, scope_id, tenant_id, actor_id,
       CASE WHEN scope_id IS NULL OR actor_id IS NULL THEN event_uid END AS unresolved_event_uid,
       min(timestamp) AS first_observed, max(timestamp) AS last_observed,
       count(*) AS signins, count(*) FILTER (WHERE outcome='failure') AS failures,
       count(*) FILTER (WHERE outcome='success') AS successes,
       count(*) FILTER (WHERE outcome='unknown') AS unknown_outcomes,
       count(DISTINCT source_ip) AS distinct_source_ips,
       count(*) FILTER (WHERE json_extract_string(raw, '$.riskLevelDuringSignIn')
          IN ('medium', 'high')) AS elevated_risk_observations,
       count(*) FILTER (WHERE json_extract_string(raw, '$.riskLevelDuringSignIn') IS NULL
          OR json_extract_string(raw, '$.riskLevelDuringSignIn')
          NOT IN ('none', 'low', 'medium', 'high')) AS unavailable_risk_observations,
       count(*) AS mfa_outcome_unknown,
       list(event_uid ORDER BY timestamp NULLS LAST, submicrosecond_ns, event_uid) AS event_uids
FROM selected
GROUP BY scope_type, scope_id, tenant_id, actor_id, unresolved_event_uid
ORDER BY failures DESC, elevated_risk_observations DESC, scope_id, actor_id, unresolved_event_uid;
