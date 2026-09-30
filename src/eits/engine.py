"""Deterministic rule execution. Evaluation labels never enter this module."""

import json

from .db import evidence, rows
from .model import canonical, digest
from .registry import RuleRegistry, resource


def revisions(*, registry=None):
    return (registry or RuleRegistry.packaged()).revisions()


def catalog(revision="baseline", *, registry=None):
    return (registry or RuleRegistry.packaged()).catalog(revision)


def rule_sql(rule_id, revision="baseline", *, registry=None):
    return (registry or RuleRegistry.packaged()).sql(rule_id, revision)


def supporting_uids(match, contract):
    try:
        values = (
            [match[column] for column in contract["columns"]]
            if "columns" in contract
            else match[contract["list_column"]]
        )
    except KeyError as exc:
        raise ValueError("rule query omitted a declared evidence column") from exc
    if (
        not isinstance(values, (list, tuple))
        or not values
        or any(not isinstance(uid, str) or not uid for uid in values)
        or len(set(values)) != len(values)
    ):
        raise ValueError("rule evidence must contain one or more unique nonempty event UIDs")
    return tuple(values)


def detect(connection, revision="baseline", *, registry=None):
    registry = registry or RuleRegistry.packaged()
    findings, event_cache = [], {}
    for rule_id, metadata in catalog(revision, registry=registry).items():
        sql = rule_sql(rule_id, revision, registry=registry)
        sql_sha = digest(sql.encode())
        grouped = {}
        for match in rows(connection, scoped_sql(sql), [metadata["provider"], metadata["source"]]):
            uids = supporting_uids(match, metadata["evidence"])
            grouped.setdefault(uids, []).append(match)
        for uids, matches in grouped.items():
            events = []
            for uid in uids:
                if uid not in event_cache:
                    found = rows(
                        connection,
                        "SELECT event_uid, source_event_id, provider, source FROM events WHERE event_uid=?",
                        [uid],
                    )
                    if not found:
                        raise ValueError(f"rule {rule_id} references unknown event: {uid}")
                    event_cache[uid] = found[0]
                event = event_cache[uid]
                if (event["provider"], event["source"]) != (
                    metadata["provider"],
                    metadata["source"],
                ):
                    raise ValueError(
                        f"rule {rule_id} evidence provider/source differs from its registry metadata"
                    )
                events.append(event)
            # Preserve the legacy ordered tuple hash for existing rule revisions.
            finding_id = (
                "finding_"
                + digest(canonical([rule_id, metadata["version"], sql_sha, uids]).encode())[:24]
            )
            findings.append(
                {
                    "finding_id": finding_id,
                    "rule_id": rule_id,
                    "rule_version": metadata["version"],
                    "sql_sha256": sql_sha,
                    "title": metadata["title"],
                    "severity": metadata["severity"],
                    "provider": metadata["provider"],
                    "source": metadata["source"],
                    "attack": metadata["attack"],
                    "event_uids": list(uids),
                    "source_event_ids": [event["source_event_id"] for event in events],
                    "observed": metadata["observed"],
                    "inferred": metadata["inferred"],
                    "unresolved": metadata["cannot_establish"],
                    "predicate_evidence": matches,
                }
            )
    return sorted(findings, key=lambda finding: (finding["rule_id"], finding["finding_id"]))


def explain(connection, finding_id, revision="baseline", *, registry=None, adapter_registry=None):
    registry = registry or RuleRegistry.packaged()
    finding = next(
        (
            item
            for item in detect(connection, revision, registry=registry)
            if item["finding_id"] == finding_id
        ),
        None,
    )
    if finding is None:
        raise ValueError("finding not found in this database/revision; run detect first")
    adapter_options = {} if adapter_registry is None else {"registry": adapter_registry}
    events = [evidence(connection, uid, **adapter_options) for uid in finding["event_uids"]]
    finding["events"] = events
    finding["rule"] = catalog(revision, registry=registry)[finding["rule_id"]]
    finding["execution"] = {
        "executed_query_sha256": digest(
            scoped_sql(rule_sql(finding["rule_id"], revision, registry=registry)).encode()
        ),
        "scope_parameters": {"provider": finding["provider"], "source": finding["source"]},
    }
    scope_fields = ("provider", "source", "scope_type", "scope_id", "tenant_id")
    scopes = sorted(
        {
            tuple(event[field] for field in scope_fields)
            for event in events
            if event["scope_type"] is not None and event["scope_id"] is not None
        },
        key=canonical,
    )
    timestamps = [event["timestamp"] for event in events if event["timestamp"] is not None]
    # An absent scope never establishes equivalence between otherwise unknown events.
    clauses = ["event_uid IN (" + ",".join("?" for _ in events) + ")"]
    parameters = list(finding["event_uids"])
    if scopes and timestamps:
        scope_sql = " AND ".join(f"{field} IS NOT DISTINCT FROM ?" for field in scope_fields)
        clauses.append(
            "(("
            + " OR ".join(f"({scope_sql})" for _ in scopes)
            + ") AND timestamp BETWEEN ? AND ?)"
        )
        parameters.extend(value for scope in scopes for value in scope)
        parameters.extend((min(timestamps), max(timestamps)))
    finding["context_timeline"] = rows(
        connection,
        """SELECT event_uid, source_event_id, timestamp,
        provider, source, scope_type, scope_id, tenant_id,
        service, action, actor_id, credential_id, outcome FROM events WHERE """
        + " OR ".join(clauses)
        + " ORDER BY timestamp NULLS LAST,event_uid",
        parameters,
    )
    finding["timeline_note"] = (
        "Supporting events plus same-provider/source/scope context between known supporting-event timestamps. Unknown scopes do not expand context. Inclusion does not establish causal or cross-cloud identity connection; inspect an event UID for exact evidence."
    )
    return finding


def scoped_sql(sql):
    """Restrict all references to events, including joins and counterevidence."""
    return (
        "WITH events AS (SELECT * FROM main.events WHERE provider=? AND source=?) "
        "SELECT * FROM (\n" + sql.rstrip().removesuffix(";") + "\n) AS scoped_query"
    )


def hunt_catalog():
    return json.loads(resource("rules/hunts.json"))


def hunt(connection, hours=24, *, hunt_id=None):
    definitions = hunt_catalog()
    hunt_id = hunt_id or next(key for key, value in definitions.items() if value.get("default"))
    if hunt_id not in definitions:
        raise ValueError("unknown hunt")
    metadata = definitions[hunt_id]
    if hours <= metadata["min_hours_exclusive"] or hours > metadata["max_hours_inclusive"]:
        raise ValueError(
            f"hunt hours must be between {metadata['min_hours_exclusive']} (exclusive) and {metadata['max_hours_inclusive']}"
        )
    return rows(
        connection,
        scoped_sql(resource(metadata["sql_path"])),
        [metadata["provider"], metadata["source"], hours],
    )
