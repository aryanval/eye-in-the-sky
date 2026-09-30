"""Repeatable CLI walkthrough using only committed official/synthetic fixtures."""
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    (ROOT / "work").mkdir(exist_ok=True)
    workspace = Path(tempfile.mkdtemp(prefix="phase1-demo-", dir=ROOT / "work"))
    database = workspace / "demo.duckdb"

    def run(*arguments):
        result = subprocess.run([sys.executable, "-m", "eits", "--db", str(database), *map(str, arguments)],
                                cwd=ROOT, text=True, capture_output=True, check=True)
        return json.loads(result.stdout)

    def save(name, value):
        (workspace / name).write_text(json.dumps(value, indent=2) + "\n")

    print("Eye in the Sky | Phase 1 | AWS only | official samples + synthetic scenarios")
    print("No accounts, cloud API calls, or LLM calls are used by this walkthrough.\n")
    official = run("ingest", "fixtures/aws/official/manifest.json")
    synthetic = run("ingest", "fixtures/aws/synthetic/manifest.json")
    print(f"1. Ingested {official['new_events']} official sample events and {synthetic['new_events']} unique synthetic events.")
    repeated = run("ingest", "fixtures/aws/synthetic/manifest.json")
    assert repeated["new_events"] == 0
    print("   Re-ingestion added 0 events; duplicate delivery is idempotent.")
    findings = run("detect")
    save("findings.json", findings)
    print(f"2. Two deterministic SQL rules produced {len(findings)} findings.")
    truth = json.loads((ROOT / "evaluation/ground_truth.json").read_text())["scenarios"]

    def select(case_id):
        scenario = next(s for s in truth if s["scenario_id"] == case_id)
        return next(f for f in findings if set(f["source_event_ids"]) == set(scenario["anchor_event_ids"]))

    example = run("explain", select("case-01")["finding_id"])
    save("evidence-case-01.json", example)
    print(f"3. Opened {example['rule_id']} / {example['finding_id']}.")
    print("   Observed:", example["observed"])
    print("   Inferred:", example["inferred"])
    for event in example["events"]:
        ref = event["source_references"][0]
        assert ref["integrity_verified"]
        print(f"   {event['timestamp']} {event['action']} | event {event['source_event_id']}")
        print(f"     {ref['category']} / {ref['source_path']} {ref['record_pointer']} / sha256 {ref['artifact_sha256'][:16]}…")
    exact_event = run("event", example["source_event_ids"][0])
    assert exact_event["raw"] == example["events"][0]["raw"]
    ref = exact_event["source_references"][0]
    exported = workspace / "exact-source.json"
    run("export-raw", ref["artifact_sha256"], exported)
    assert hashlib.sha256(exported.read_bytes()).hexdigest() == ref["artifact_sha256"]
    print("4. Exported and hash-verified the exact original source file; raw evidence survives independently of input paths.")
    hunt = run("hunt")
    save("hunt.json", hunt)
    late = next(r for r in hunt["results"] if r["account_id"] == "900000000003")
    assert late["sensitive_actions"] == 1
    print(f"5. HUNT-001 returned {len(hunt['results'])} credential leads. It includes the delayed attachment missed by the 30-minute detection.")
    benign = run("explain", select("case-06")["finding_id"])
    save("benign-lookalike.json", benign)
    print("6. Case-06 is an authorized bootstrap in the synthetic ground truth. The same observable behavior alerts: a real false positive on this fixture.")
    baseline_path, candidate_path = workspace / "baseline.json", workspace / "restart-aware.json"
    run("evaluate", "--output", baseline_path)
    run("evaluate", "--revision", "restart-aware", "--output", candidate_path)
    baseline, candidate = json.loads(baseline_path.read_text()), json.loads(candidate_path.read_text())
    print("7. Fixture-specific evaluation (ambiguous cases are reported separately):")
    for name, report in (("baseline", baseline), ("restart-aware", candidate)):
        for rule, result in report["rules"].items():
            m = result["metrics"]
            print(f"   {name:13} {rule}: TP={m['tp']} FP={m['fp']} FN={m['fn']} precision={m['precision']:.3f} recall={m['recall']:.3f}")
    print("   The restart-aware candidate removes one benign alert and misses one additional malicious scenario. Baseline stays the default.")
    summary = {"phase": 1, "official_events": official["new_events"], "synthetic_events": synthetic["new_events"],
               "baseline_findings": len(findings), "hunt_results": len(hunt["results"]),
               "evidence_export_verified": True, "implemented_sources": ["aws.cloudtrail"],
               "live_account_validated": False}
    save("summary.json", summary)
    print("\nWalkthrough artifacts:", workspace.relative_to(ROOT))
    print("Phase 1 only. Azure/Entra/GCP/endpoint parsers and personal live validation are not implemented.")


if __name__ == "__main__":
    main()
