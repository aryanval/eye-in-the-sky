# Eye in the Sky

A local multicloud detection and threat-hunting project: five telemetry sources,
six SQL detections, three exploratory hunts, reproducible FP/FN evaluation and
findings that resolve to exact retained source events.

Implemented sources are **AWS CloudTrail, Azure Activity Logs, Entra sign-ins,
Entra directory audits and GCP Cloud Audit Logs**. Validation uses official public
schemas, retained vendor examples and independently generated synthetic scenarios.
**Live cloud validation: NO.** No cloud account, tenant, billing or credentials
are required.

## Run the complete local loop

From the repository root, using Python 3.11 or newer:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python scripts/demo.py
```

CI checks Python 3.11 and 3.14 against a non-editable package installation. Package
installation requires a package source; analysis, tests and the walkthrough use
committed files and run offline. No Docker or cloud SDK is needed.

The walkthrough imports all five sources into one DuckDB store, runs all six
rules, explains findings from every provider family, verifies exact source-byte
exports, runs all three hunts, inspects an authorized lookalike that alerts and
prints evaluation metrics. Each run creates a fresh ignored `work/phase2-demo-*`
directory. The original AWS walkthrough remains in `scripts/demo_phase1.py`.

## Use the CLI directly

```sh
.venv/bin/python -m eits ingest fixtures/aws/synthetic/manifest.json
.venv/bin/python -m eits ingest fixtures/azure/activity/synthetic/manifest.json
.venv/bin/python -m eits ingest fixtures/azure/entra-signin/synthetic/manifest.json
.venv/bin/python -m eits ingest fixtures/azure/entra-audit/synthetic/manifest.json
.venv/bin/python -m eits ingest fixtures/gcp/synthetic/manifest.json
.venv/bin/python -m eits status
.venv/bin/python -m eits detect
.venv/bin/python -m eits hunt --hunt-id HUNT-002 --hours 24
.venv/bin/python -m eits evaluate --manifest fixtures/gcp/synthetic/manifest.json --truth evaluation/gcp-ground-truth.json
```

Use a returned finding ID with `eits explain FINDING_ID`, or a supporting UID with
`eits event EVENT_UID`. Use `eits export-raw SHA256 OUTPUT` to export an artifact
identified in `source_references`. Commands return JSON. Put `--db PATH` before
the subcommand to choose another database. Existing exports and report files are
never overwritten. Bare `evaluate` still evaluates the original AWS corpus;
`--revision restart-aware` retains its published tuning comparison.

## What the project demonstrates

Source adapters map defensible time, scope, actor, credential, action, resource
and outcome fields into a small common model. Unknown values remain unknown;
provider-specific fields and original JSON remain available. Scope namespaces
preserve the differences between accounts, subscriptions, tenants and log-owning
projects/organizations. See [ARCHITECTURE.md](ARCHITECTURE.md) and the exact
[per-source mappings](DATA_SOURCES.md).

[Six detections](DETECTION_CATALOG.md) include five two-event correlations and a
single-event GCP public-bucket policy-delta rule. Each has executable SQL,
versioned metadata, required telemetry, observed facts, inference, unresolved
facts, tuning guidance and limitations. [Three hunts](HUNTS.md) return broader
investigative leads, without a malicious classification.

Findings carry exact supporting UIDs, rule/version and query hashes. `explain`
verifies retained artifact hashes, manifests and record pointers before showing
raw events and a scoped context timeline. Timeline inclusion does not establish
causality. Labels live separately from detector input.

## Measured behavior and boundaries

[EVALUATION.md](EVALUATION.md) records TP, FP, FN, TN, precision, overall recall,
complete-telemetry recall and ambiguous alerts. Authorized lookalikes alert;
missing fields, absent records, unsupported behaviors and delayed actions cause
misses. These are small synthetic-corpus results, not production performance
estimates or an independently blinded benchmark. The AWS baseline and candidate
retain their original findings and scores.

| Source | Parser | Complete official fixture validated | Synthetic corpus | Live validated |
|---|---|---|---|---|
| AWS CloudTrail | Yes | Yes, seven events | Yes | **NO** |
| Azure Activity REST EventData | Yes | Yes, one event | Yes | **NO** |
| Entra Graph v1.0 sign-ins | Yes | No; abbreviated excerpt retained | Yes | **NO** |
| Entra Graph v1.0 directory audits | Yes | No; abbreviated excerpt retained | Yes | **NO** |
| GCP Audit LogEntry | Yes | No; abbreviated excerpts retained | Yes | **NO** |

Abbreviated or invalid vendor examples remain unchanged documentation evidence.
Executable synthetic events are independently authored from public schemas and
clearly labeled; they are never presented as repaired official fixtures. See
[DATA_SOURCES.md](DATA_SOURCES.md) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Here, **multicloud** means multiple cloud formats share an investigation,
detection, hunt, evidence and evaluation interface. It does not establish unified
enterprise identity, cross-cloud causal attribution or production administration.
No identity is joined across clouds by email, username, IP or display name.

Successful records do not prove effective privilege, durable configuration,
public reachability, exploitation or intent. Parsers support the explicitly
listed representations, not every export envelope or full vendor-schema
validation. There is no external benchmark, production load test or live cloud
validation. Runtime analysis has no network client; DuckDB external I/O is
disabled. Python network-blocking tests are not an operating-system sandbox.

## Development and milestone evidence

```sh
.venv/bin/python -m ruff check src tests scripts
.venv/bin/python -m ruff format --check src tests scripts
.venv/bin/python -m unittest discover -s tests -v
```

[PHASE2_REPORT.md](PHASE2_REPORT.md) records completion checks, provider counts,
CI, compatibility and the supported claim table. [PHASE1_REPORT.md](PHASE1_REPORT.md)
and [REFACTOR_REPORT.md](REFACTOR_REPORT.md) preserve historical milestone results.
No frontend, LLM, endpoint collection, cloud collector, account creation or
infrastructure deployment is included.
