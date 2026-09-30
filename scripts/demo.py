"""Offline multicloud CLI walkthrough using committed, attributed fixture files."""

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = (
    "fixtures/aws/official/manifest.json",
    "fixtures/aws/synthetic/manifest.json",
    "fixtures/azure/activity/official/manifest.json",
    "fixtures/azure/activity/synthetic/manifest.json",
    "fixtures/azure/entra-signin/synthetic/manifest.json",
    "fixtures/azure/entra-audit/synthetic/manifest.json",
    "fixtures/gcp/synthetic/manifest.json",
)
EVALUATIONS = (
    ("aws", MANIFESTS[1], "evaluation/ground_truth.json"),
    ("azure-activity", MANIFESTS[3], "evaluation/azure-activity-ground-truth.json"),
    ("entra", MANIFESTS[5], "evaluation/entra-ground-truth.json"),
    ("gcp", MANIFESTS[6], "evaluation/gcp-ground-truth.json"),
)


def main():
    (ROOT / "work").mkdir(exist_ok=True)
    workspace = Path(tempfile.mkdtemp(prefix="phase2-demo-", dir=ROOT / "work"))
    database = workspace / "demo.duckdb"

    def run(*arguments):
        result = subprocess.run(
            [sys.executable, "-m", "eits", "--db", str(database), *map(str, arguments)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
        )
        return json.loads(result.stdout)

    def save(name, value):
        (workspace / name).write_text(json.dumps(value, indent=2) + "\n")

    print("Eye in the Sky | Phase 2 | AWS + Azure/Entra + GCP | local, offline")
    print("Official AWS/Azure examples and independent synthetic scenarios; live validation: NO.\n")
    counts = {}
    for manifest in MANIFESTS:
        result = run("ingest", manifest)
        counts[manifest] = result["new_events"]
        print(f"1. {manifest}: {result['new_events']} new events")
    assert run("ingest", MANIFESTS[-1])["new_events"] == 0
    status = run("status")
    assert len(status["events"]) == 5
    save("status.json", status)
    print("   Five sources share one store; repeated GCP import adds no events.")

    findings = run("detect")
    save("findings.json", findings)
    rule_ids = sorted({f["rule_id"] for f in findings})
    assert len(rule_ids) == 6
    assert {f["provider"] for f in findings} == {"aws", "azure", "gcp"}
    print(f"2. Six rules produced {len(findings)} findings across all three provider families.")
    for rule in rule_ids:
        finding = next(f for f in findings if f["rule_id"] == rule)
        detail = run("explain", finding["finding_id"])
        save(f"evidence-{rule}.json", detail)
        assert [e["event_uid"] for e in detail["events"]] == finding["event_uids"]
        print(f"3. {rule}: {len(detail['events'])} exact supporting event(s)")
        print("   Observed:", detail["observed"])
        print("   Inference:", detail["inferred"])
        for event in detail["events"]:
            exact = run("event", event["event_uid"])
            assert exact["raw"] == event["raw"]
            assert all(r["integrity_verified"] for r in exact["source_references"])
        ref = detail["events"][0]["source_references"][0]
        exported = workspace / f"source-{rule}.json"
        run("export-raw", ref["artifact_sha256"], exported)
        assert hashlib.sha256(exported.read_bytes()).hexdigest() == ref["artifact_sha256"]
    print("   Original artifact exports verified by SHA-256 for every rule.")

    hunt_counts = {}
    for hunt_id in ("HUNT-001", "HUNT-002", "HUNT-003"):
        result = run("hunt", "--hunt-id", hunt_id)
        save(f"{hunt_id}.json", result)
        assert result["results"]
        hunt_counts[hunt_id] = len(result["results"])
        print(f"4. {hunt_id}: {len(result['results'])} exploratory leads, not malicious verdicts.")

    truth = json.loads((ROOT / "evaluation/ground_truth.json").read_text())["scenarios"]
    benign_case = next(s for s in truth if s["scenario_id"] == "case-06")
    benign = next(
        f for f in findings if set(f["source_event_ids"]) == set(benign_case["anchor_event_ids"])
    )
    save("benign-lookalike.json", run("explain", benign["finding_id"]))
    print("5. AWS case-06 is authorized bootstrap in separate synthetic ground truth.")
    print("   It still alerts: a retained false positive, not proof of malicious intent.")

    metrics = {}
    print("6. Exact-anchor evaluation; ambiguous cases are excluded from precision/recall:")
    for name, manifest, labels in EVALUATIONS:
        report = run("evaluate", "--manifest", manifest, "--truth", labels)
        save(f"evaluation-{name}.json", report)
        for rule, result in report["rules"].items():
            m = result["metrics"]
            metrics[rule] = m
            print(
                f"   {rule}: TP={m['tp']} FP={m['fp']} FN={m['fn']} TN={m['tn']} precision={m['precision']:.3f} recall={m['recall']:.3f}"
            )
    candidate = run("evaluate", "--revision", "restart-aware")
    save("evaluation-aws-restart-aware.json", candidate)
    assert candidate["rules"]["EITS-AWS-002"]["metrics"]["fn"] == 4
    print("   Preserved AWS candidate: one fewer FP, one more FN. Baseline stays the default.")
    assert len(metrics) == 6
    save(
        "summary.json",
        {
            "phase": 2,
            "ingested_events": counts,
            "baseline_findings": len(findings),
            "hunt_results": hunt_counts,
            "rules": rule_ids,
            "metrics": metrics,
            "implemented_sources": [s["source"] for s in status["sources"] if s["implemented"]],
            "evidence_export_verified": True,
            "live_account_validated": False,
        },
    )
    print("\nWalkthrough artifacts:", workspace.relative_to(ROOT))


if __name__ == "__main__":
    main()
