"""Evaluation alone reads labels. Detectors receive only normalized events."""

import json
import platform
from collections import defaultdict
from importlib.resources import files
from pathlib import Path

import duckdb

from .db import connect, evidence, ingest
from .engine import catalog, detect, rule_sql, scoped_sql
from .model import canonical, digest
from .registry import RuleRegistry


def ratio(numerator, denominator):
    return round(numerator / denominator, 6) if denominator else None


def score(findings, scenarios, split="all", *, revision="baseline", registry=None):
    """Score exact anchor sets of any size; UID anchors support multiple sources.

    A corpus uses either legacy source IDs or event UIDs consistently. Ownership
    is per rule, so the same evidence may support independent rule scenarios.
    """
    if split not in {"all", "development", "holdout"}:
        raise ValueError("unknown evaluation split")
    modes = {
        "uid" if "anchor_event_uids" in scenario or "available_event_uids" in scenario else "id"
        for scenario in scenarios
    }
    if len(modes) > 1:
        raise ValueError("ground truth must not mix source event IDs and event UIDs")
    uid_mode = modes == {"uid"}
    anchor_key = "anchor_event_uids" if uid_mode else "anchor_event_ids"
    available_key = "available_event_uids" if uid_mode else "available_event_ids"
    finding_key = "event_uids" if uid_mode else "source_event_ids"
    if not uid_mode:
        sources = {
            (finding.get("provider"), finding.get("source"))
            for finding in findings
            if finding.get("provider") is not None or finding.get("source") is not None
        }
        if len(sources) > 1:
            raise ValueError("multi-source evaluation requires event UID anchors")
        resolved_ids = {}
        for finding in findings:
            if "event_uids" not in finding:
                continue
            if len(finding["event_uids"]) != len(finding["source_event_ids"]):
                raise ValueError("finding source event IDs and UIDs must align")
            for source_id, uid in zip(finding["source_event_ids"], finding["event_uids"]):
                if source_id in resolved_ids and resolved_ids[source_id] != uid:
                    raise ValueError("ambiguous source event IDs require event UID anchors")
                resolved_ids[source_id] = uid
    for finding in findings:
        values = finding.get(finding_key)
        if (
            not isinstance(values, list)
            or not values
            or any(not isinstance(value, str) or not value for value in values)
            or len(set(values)) != len(values)
        ):
            raise ValueError(
                f"finding {finding_key} must contain unique nonempty identifiers; use UID anchors for unavailable source IDs"
            )
    owners = {}
    by_id = {s["scenario_id"]: s for s in scenarios}
    if len(by_id) != len(scenarios):
        raise ValueError("ground truth scenario IDs must be unique")
    for scenario in scenarios:
        if scenario["label"] not in {"malicious", "benign", "ambiguous"}:
            raise ValueError("unknown ground-truth label")
        for key in (anchor_key, available_key):
            values = scenario.get(key)
            if (
                not isinstance(values, list)
                or (key == anchor_key and not values)
                or any(not isinstance(value, str) or not value for value in values)
                or len(set(values)) != len(values)
            ):
                raise ValueError(
                    f"ground truth {key} must contain unique nonempty identifiers; anchors cannot be empty"
                )
        for event_id in set(scenario[available_key] + scenario[anchor_key]):
            owner_key = (scenario["rule_id"], event_id)
            if owner_key in owners and owners[owner_key] != scenario["scenario_id"]:
                raise ValueError("ground truth shares an event across scenarios for the same rule")
            owners[owner_key] = scenario["scenario_id"]
    output = {}
    rule_ids = dict.fromkeys(
        [
            *catalog(revision, registry=registry),
            *(scenario["rule_id"] for scenario in scenarios),
            *(finding["rule_id"] for finding in findings),
        ]
    )
    for rule_id in rule_ids:
        grouped, unexpected = defaultdict(list), []
        for finding in findings:
            if finding["rule_id"] != rule_id:
                continue
            owner_set = {owners.get((rule_id, event_id)) for event_id in finding[finding_key]}
            if len(owner_set) == 1 and None not in owner_set:
                owner = next(iter(owner_set))
                if split != "all" and by_id[owner]["split"] != split:
                    continue
                if by_id[owner]["rule_id"] == rule_id:
                    grouped[owner].append(finding)
                else:
                    unexpected.append(finding["finding_id"])
            else:
                selected = [by_id[o] for o in owner_set if o in by_id]
                if split == "all" or not selected or any(s["split"] == split for s in selected):
                    unexpected.append(finding["finding_id"])
        counts = dict(
            tp=0,
            fp=len(unexpected),
            fn=0,
            tn=0,
            ambiguous=0,
            ambiguous_alerted=0,
            complete_telemetry_tp=0,
            complete_telemetry_fn=0,
            duplicate_findings=0,
        )
        details = []
        for scenario in scenarios:
            if scenario["rule_id"] != rule_id or (split != "all" and scenario["split"] != split):
                continue
            alerts = grouped[scenario["scenario_id"]]
            valid = [f for f in alerts if set(scenario[anchor_key]) == set(f[finding_key])]
            label = scenario["label"]
            if label == "ambiguous":
                result = "unscored_alert" if alerts else "unscored_no_alert"
                counts["ambiguous"] += 1
                counts["ambiguous_alerted"] += bool(alerts)
            elif label == "benign":
                result = "fp" if alerts else "tn"
                counts[result] += 1
                counts["duplicate_findings"] += max(0, len(alerts) - 1)
            else:
                result = "tp" if valid else "fn"
                counts[result] += 1
                if scenario["telemetry_complete"]:
                    counts["complete_telemetry_" + result] += 1
                invalid = [f for f in alerts if f not in valid]
                if invalid:
                    counts["fp"] += 1  # Wrong evidence does not rescue the missed attack.
                counts["duplicate_findings"] += max(0, len(valid) - 1) + max(0, len(invalid) - 1)
            details.append(
                {
                    **scenario,
                    "result": result,
                    "finding_ids": [f["finding_id"] for f in alerts],
                    "correct_evidence_match": bool(valid),
                }
            )
        counts["precision"] = ratio(counts["tp"], counts["tp"] + counts["fp"])
        counts["recall"] = ratio(counts["tp"], counts["tp"] + counts["fn"])
        counts["complete_telemetry_recall"] = ratio(
            counts["complete_telemetry_tp"],
            counts["complete_telemetry_tp"] + counts["complete_telemetry_fn"],
        )
        output[rule_id] = {
            "metrics": counts,
            "scenario_coverage": {
                "evaluated": len(details),
                "malicious_detected": counts["tp"],
                "malicious_total": counts["tp"] + counts["fn"],
                "ambiguous_excluded_from_precision_recall": counts["ambiguous"],
            },
            "scenarios": details,
            "unexpected_findings": unexpected,
        }
    return output


def package_hashes():
    """Hash every packaged Python, SQL, and rule JSON input to execution."""
    hashes = {}

    def visit(directory, prefix=""):
        for item in directory.iterdir():
            name = prefix + item.name
            if item.is_dir() and item.name != "__pycache__":
                visit(item, name + "/")
            elif item.is_file() and (
                name.endswith((".py", ".sql"))
                or name.startswith("rules/")
                and name.endswith(".json")
            ):
                hashes[name] = digest(item.read_bytes())

    visit(files("eits"))
    return dict(sorted(hashes.items()))


def evaluate(
    manifest_path,
    truth_path,
    revision="baseline",
    split="all",
    *,
    registry=None,
    adapter_registry=None,
):
    registry = registry or RuleRegistry.packaged()
    manifest_bytes, truth_bytes = Path(manifest_path).read_bytes(), Path(truth_path).read_bytes()
    truth = json.loads(truth_bytes)
    manifest = json.loads(manifest_bytes)
    registry = registry.for_source(manifest["provider"], manifest["source"])
    if truth["dataset_id"] != manifest["dataset_id"]:
        raise ValueError("ground truth and fixture dataset IDs differ")
    if split not in {"all", "development", "holdout"}:
        raise ValueError("unknown evaluation split")
    connection = connect()
    try:
        adapter_options = {} if adapter_registry is None else {"registry": adapter_registry}
        ingestion = ingest(connection, manifest_path, **adapter_options)
        if not any(
            "anchor_event_uids" in scenario or "available_event_uids" in scenario
            for scenario in truth["scenarios"]
        ):
            collision = connection.execute("""SELECT source_event_id FROM events
                WHERE source_event_id IS NOT NULL GROUP BY source_event_id HAVING count(*) > 1 LIMIT 1""").fetchone()
            if collision:
                raise ValueError(
                    "ambiguous source event IDs in evaluation database require event UID anchors"
                )
        findings = detect(connection, revision, registry=registry)
        verified = set()
        for finding in findings:
            for uid in finding["event_uids"]:
                if uid not in verified:
                    evidence(connection, uid, **adapter_options)
                    verified.add(uid)
        hashes = package_hashes()
        report = {
            "report_version": 2,
            "rule_revision": revision,
            "split": split,
            "schema_version": int(
                connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0]
            ),
            "unit": "One rule/scenario alert opportunity; duplicate findings cannot increase TP. Wrong-evidence or unassigned findings are FP. Ambiguous cases are unscored.",
            "limitation": "Metrics are specific to original synthetic fixtures. This is not a production-performance estimate or an independently blinded benchmark.",
            "dataset_id": truth["dataset_id"],
            "manifest_sha256": digest(manifest_bytes),
            "ground_truth_sha256": digest(truth_bytes),
            "ingestion": ingestion,
            "python_version": platform.python_version(),
            "duckdb_version": duckdb.__version__,
            "code_sha256": {name: sha for name, sha in hashes.items() if name.endswith(".py")},
            "resource_sha256": {
                name: sha for name, sha in hashes.items() if not name.endswith(".py")
            },
            "rule_catalog_sha256": digest(canonical(catalog(revision, registry=registry)).encode()),
            "sql_sha256": {
                rule: digest(rule_sql(rule, revision, registry=registry).encode())
                for rule in catalog(revision, registry=registry)
            },
            "executed_query_sha256": {
                rule: digest(scoped_sql(rule_sql(rule, revision, registry=registry)).encode())
                for rule in catalog(revision, registry=registry)
            },
            "execution_scope": {
                rule: {key: metadata[key] for key in ("provider", "source")}
                for rule, metadata in catalog(revision, registry=registry).items()
            },
            "evidence_events_verified": len(verified),
            "rules": score(
                findings, truth["scenarios"], split, revision=revision, registry=registry
            ),
            "findings": findings,
        }
        return report
    finally:
        connection.close()
