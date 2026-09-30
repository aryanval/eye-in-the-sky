"""Evaluation alone reads labels. Detectors receive only normalized events."""
import json
import platform
from collections import defaultdict
from importlib.resources import files
from pathlib import Path

import duckdb

from .db import connect, evidence, ingest
from .engine import catalog, detect, resource
from .model import canonical, digest


def ratio(numerator, denominator):
    return round(numerator / denominator, 6) if denominator else None


def score(findings, scenarios, split="all"):
    owners = {}
    by_id = {s["scenario_id"]: s for s in scenarios}
    for scenario in scenarios:
        if scenario["label"] not in {"malicious", "benign", "ambiguous"}:
            raise ValueError("unknown ground-truth label")
        for event_id in set(scenario["available_event_ids"] + scenario["anchor_event_ids"]):
            if event_id in owners and owners[event_id] != scenario["scenario_id"]:
                raise ValueError("ground truth shares an event across scenarios")
            owners[event_id] = scenario["scenario_id"]
    output = {}
    for rule_id in catalog():
        grouped, unexpected = defaultdict(list), []
        for finding in findings:
            if finding["rule_id"] != rule_id:
                continue
            owner_set = {owners.get(e) for e in finding["source_event_ids"]}
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
        counts = dict(tp=0, fp=len(unexpected), fn=0, tn=0, ambiguous=0, ambiguous_alerted=0,
                      complete_telemetry_tp=0, complete_telemetry_fn=0, duplicate_findings=0)
        details = []
        for scenario in scenarios:
            if scenario["rule_id"] != rule_id or (split != "all" and scenario["split"] != split):
                continue
            alerts = grouped[scenario["scenario_id"]]
            valid = [f for f in alerts if set(scenario["anchor_event_ids"]) == set(f["source_event_ids"])]
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
            details.append({**scenario, "result": result, "finding_ids": [f["finding_id"] for f in alerts],
                            "correct_evidence_match": bool(valid)})
        counts["precision"] = ratio(counts["tp"], counts["tp"] + counts["fp"])
        counts["recall"] = ratio(counts["tp"], counts["tp"] + counts["fn"])
        counts["complete_telemetry_recall"] = ratio(counts["complete_telemetry_tp"], counts["complete_telemetry_tp"] + counts["complete_telemetry_fn"])
        output[rule_id] = {"metrics": counts, "scenario_coverage": {"evaluated": len(details), "malicious_detected": counts["tp"],
                          "malicious_total": counts["tp"] + counts["fn"], "ambiguous_excluded_from_precision_recall": counts["ambiguous"]},
                          "scenarios": details, "unexpected_findings": unexpected}
    return output


def evaluate(manifest_path, truth_path, revision="baseline", split="all"):
    manifest_bytes, truth_bytes = Path(manifest_path).read_bytes(), Path(truth_path).read_bytes()
    truth = json.loads(truth_bytes)
    manifest = json.loads(manifest_bytes)
    if truth["dataset_id"] != manifest["dataset_id"]:
        raise ValueError("ground truth and fixture dataset IDs differ")
    if split not in {"all", "development", "holdout"}:
        raise ValueError("unknown evaluation split")
    connection = connect()
    try:
        ingestion = ingest(connection, manifest_path)
        findings = detect(connection, revision)
        verified = set()
        for finding in findings:
            for uid in finding["event_uids"]:
                if uid not in verified:
                    evidence(connection, uid)
                    verified.add(uid)
        report = {
            "report_version": 1, "rule_revision": revision, "split": split,
            "unit": "One rule/scenario alert opportunity; duplicate findings cannot increase TP. Wrong-evidence or unassigned findings are FP. Ambiguous cases are unscored.",
            "limitation": "Metrics are specific to original synthetic fixtures. This is not a production-performance estimate or an independently blinded benchmark.",
            "dataset_id": truth["dataset_id"], "manifest_sha256": digest(manifest_bytes),
            "ground_truth_sha256": digest(truth_bytes), "ingestion": ingestion,
            "python_version": platform.python_version(), "duckdb_version": duckdb.__version__,
            "code_sha256": {name: digest(files("eits").joinpath(name).read_bytes())
                            for name in ("model.py", "db.py", "engine.py", "evaluation.py")},
            "sql_sha256": {rule: digest(resource(f"sql/{rule}.sql").encode()) for rule in catalog()},
            "evidence_events_verified": len(verified),
            "rules": score(findings, truth["scenarios"], split), "findings": findings,
        }
        return report
    finally:
        connection.close()
