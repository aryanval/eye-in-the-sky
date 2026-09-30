# Threat hunts — Phase 1

## HUNT-001 — First 24 hours of newly created access keys

**Hypothesis:** a newly issued persistent credential may be used for unexpected
administrative activity, including behavior that falls outside a detection's
time window or exact action set.

**Required telemetry:** CloudTrail `CreateAccessKey` records plus subsequent
management events, account, event time and issued/caller key identifiers. Missing
key IDs, account or time are retained as unresolvable creations. No historical
inventory, paid service, reputation feed or personal account is required.

The exact executable query is [HUNT-001.sql](src/eits/sql/HUNT-001.sql).

```sh
.venv/bin/python -m eits hunt --hours 24
```

Read the query in four steps:

1. The `creations` CTE selects successful key-creation records and extracts the
   issued key ID. It does not require an administrative attachment.
2. A left join finds events with the same account and exact caller key ID from
   creation time through the requested window. Unlike the sequence detector, the
   hunt includes equal-time observations because it does not assert ordering.
3. Aggregation returns first/last use, event count, distinct services/actions/IPs,
   failures and sensitive-action attempts. Sensitive counts include unsuccessful
   attempts; the separate failure count and raw events provide that context.
4. It returns creation and use event UIDs/source IDs, orders investigative leads
   by sensitive actions and failures, and preserves zero-use and unresolvable rows.

The 24-hour default is an investigation window, not a learned baseline. Its upper
bound is inclusive. Counts cover only supplied events. Missing or non-IP source
addresses do not count as distinct IPs, but remain in raw evidence.

**What increases suspicion:** an administrative policy attachment, a logging stop,
public ingress changes, or repeated denied calls followed by sensitive success.
Source diversity can guide review but is not a reputation or location verdict.

**What decreases suspicion:** verified planned rotation/bootstrap, expected
provisioning actions, established ownership and an authorized change. Those facts
need their own evidence; the query does not infer them from an actor name.

**Evidence needed before a malicious conclusion:** credential ownership, change
authorization, identity/session history, effective permissions, prior behavior
and downstream effects. No-use-observed does not establish an unused or inactive
key. A missing creation response prevents direct key attribution. STS role
transitions require a separate investigation not implemented in this phase.

**Verified fixture behavior:** the query returns 12 leads: one unresolvable
creation and three with no direct key use observed. Case-03's attachment at 45
minutes appears in the hunt even though EITS-AWS-001's 30-minute detector misses
it. Open any returned `creation_uid` or `use_event_uids` using `eits event`.

This is a hunt, not an alert rule or malicious classification. A useful result
can be benign, ambiguous or incomplete.
