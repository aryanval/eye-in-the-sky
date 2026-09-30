"""Deterministic rule execution. Evaluation labels never enter this module."""
import json
from importlib.resources import files

from .db import evidence, rows
from .model import canonical, digest


def resource(path):
    return files("eits").joinpath(path).read_text()


def catalog(revision="baseline"):
    if revision not in {"baseline", "restart-aware"}:
        raise ValueError("unknown rule revision")
    result = json.loads(resource("rules/catalog.json"))
    if revision == "restart-aware":
        for rule_id, updates in json.loads(resource("rules/restart-aware.json")).items():
            result[rule_id].update(updates)
    return result


def rule_sql(rule_id, revision="baseline"):
    suffix = "-restart-aware" if rule_id == "EITS-AWS-002" and revision == "restart-aware" else ""
    return resource(f"sql/{rule_id}{suffix}.sql")


def detect(connection, revision="baseline"):
    findings = []
    for rule_id, metadata in catalog(revision).items():
        sql = rule_sql(rule_id, revision)
        sql_sha = digest(sql.encode())
        grouped = {}
        for match in rows(connection, sql):
            pair = (match["start_uid"], match["end_uid"])
            grouped.setdefault(pair, []).append(match)
        for pair, matches in grouped.items():
            finding_id = "finding_" + digest(canonical([rule_id, metadata["version"], sql_sha, pair]).encode())[:24]
            findings.append({"finding_id": finding_id, "rule_id": rule_id,
                "rule_version": metadata["version"], "sql_sha256": sql_sha,
                "title": metadata["title"], "severity": metadata["severity"],
                "provider": "aws", "source": "aws.cloudtrail", "attack": metadata["attack"],
                "event_uids": list(pair),
                "source_event_ids": [matches[0]["start_event_id"], matches[0]["end_event_id"]],
                "observed": metadata["observed"], "inferred": metadata["inferred"],
                "unresolved": metadata["cannot_establish"], "predicate_evidence": matches})
    return sorted(findings, key=lambda f: (f["rule_id"], f["finding_id"]))


def explain(connection, finding_id, revision="baseline"):
    finding = next((x for x in detect(connection, revision) if x["finding_id"] == finding_id), None)
    if finding is None:
        raise ValueError("finding not found in this database/revision; run detect first")
    finding["events"] = [evidence(connection, uid) for uid in finding["event_uids"]]
    finding["rule"] = catalog(revision)[finding["rule_id"]]
    match = finding["predicate_evidence"][0]
    finding["context_timeline"] = rows(connection, """SELECT event_uid, source_event_id, timestamp,
        service, action, actor_id, credential_id, outcome FROM events
        WHERE account_id=? AND timestamp BETWEEN ? AND ? ORDER BY timestamp,event_uid""",
        [match["account_id"], match["started_at"], match["ended_at"]])
    finding["timeline_note"] = "Same-account time-window context. Inclusion does not establish causal connection; inspect an event UID for exact evidence."
    return finding


def hunt(connection, hours=24):
    if hours <= 0 or hours > 24 * 31:
        raise ValueError("hunt hours must be between 0 (exclusive) and 744")
    return rows(connection, resource("sql/HUNT-001.sql"), [hours])
