# Eye in the Sky

Local detection engineering with SQL correlations, reproducible evaluation, and
findings that resolve to exact source events.

**Phase 1 implements AWS CloudTrail only.** Multicloud support is the project
direction; Azure, Entra, GCP and endpoint parsers are not implemented. This phase
has two AWS detections, one hunt, seven official AWS examples and 24 original
synthetic scenarios. No cloud account is required.

The shared architecture has source adapters, typed cloud scopes, a data-driven
rule registry and findings with one or more supporting events. Azure/Entra/GCP
source names are reserved in the registry; their parsers are not implemented.
[ARCHITECTURE.md](ARCHITECTURE.md) documents the interfaces and database migration.
[REFACTOR_REPORT.md](REFACTOR_REPORT.md) records regression results and exact
compatibility effects.

This is an independent public learning project. No employer/customer code, data,
prompts, schemas, architecture, detection rules or incident sequences were used.
Synthetic scenarios are fictional and are not reconstructions of work incidents.

## Run the complete local loop

From the repository root, using Python 3.11 or newer:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python scripts/demo.py
```

Tested locally with Python 3.14.6, DuckDB 1.5.6 and pytz 2026.4. CI checks Python
3.11 and 3.14. Dependency installation needs a package source; the runtime, tests and walkthrough
use committed files and run offline. No Docker, cloud SDK or credentials needed.

The walkthrough ingests 7 official sample events and 240 unique synthetic events,
runs both rules, opens a finding, verifies its original source bytes, runs the hunt,
inspects a benign lookalike and compares baseline/candidate evaluation. Each run
creates a fresh ignored `work/phase1-demo-*` directory with a database and JSON
evidence. It currently produces 10 baseline findings and 12 hunt leads.

## Use the CLI directly

```sh
.venv/bin/python -m eits ingest fixtures/aws/official/manifest.json
.venv/bin/python -m eits ingest fixtures/aws/synthetic/manifest.json
.venv/bin/python -m eits status
.venv/bin/python -m eits detect
.venv/bin/python -m eits explain finding_6fba7239655f77997b685934
.venv/bin/python -m eits event 403a21f0-7bd4-509e-9b23-27ca2720f39d
.venv/bin/python -m eits hunt --hours 24
.venv/bin/python -m eits evaluate
.venv/bin/python -m eits evaluate --revision restart-aware
```

The example finding ID is deterministic for the committed baseline SQL and
fixtures. If either changes, use the ID returned by `detect`. Commands return
formatted JSON. To select another database, put `--db PATH` before the subcommand.
Use `export-raw SHA256 OUTPUT` to export an original source file identified in an
event's `source_references`. Existing export/report files are never overwritten.

## What this demonstrates

The problem is understanding whether a proposed security analytic actually
matches its stated behavior, how often it fails on explicit scenarios, and what
evidence an analyst can inspect. The project makes that loop repeatable without
access to enterprise cloud telemetry.

Events are projected into a small common model for time, source, scoped identity,
credential, action, resource, outcome and authentication/privilege context.
CloudTrail-specific details and original JSON remain available. Unknown values
stay unknown. See [ARCHITECTURE.md](ARCHITECTURE.md).

Detections are readable SQL plus versioned metadata. Both require multiple events,
identity/credential joins and time windows. [DETECTION_CATALOG.md](DETECTION_CATALOG.md)
states exact predicates, evidence fields, ATT&CK mappings, false positives and
limits. [HUNTS.md](HUNTS.md) explains the separate 24-hour credential-use query.

Each finding includes rule/version/query hash, supporting event IDs, matching field
values, observed facts, an explicitly marked inference and unresolved questions.
`explain` verifies stored source hashes and record references, and includes a
provider/source/scope context timeline. A timeline entry is context, not proof of causality.

## Measured behavior

These are **synthetic-fixture results**, not estimates of production precision or
recall. Each rule has six malicious, four benign and two ambiguous scenarios;
two malicious scenarios per rule have missing telemetry. Ambiguous cases are
reported separately and never silently classified as benign.

| Rule / revision | TP | FP | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|
| EITS-AWS-001 baseline | 2 | 1 | 4 | 66.7% | 33.3% |
| EITS-AWS-002 baseline | 3 | 2 | 3 | 60.0% | 50.0% |
| EITS-AWS-002 restart-aware candidate | 2 | 1 | 4 | 66.7% | 33.3% |

The candidate suppresses a maintenance false positive but also misses a malicious
sequence that restores logging before changing ingress. **Baseline remains the
default.** No allowlist or ground-truth label is used to improve the score.
The original results, scenarios, code hashes and tuning rationale are retained in
[EVALUATION.md](EVALUATION.md) and [evaluation/](evaluation/).

## Source and validation boundaries

"Multicloud" will mean provider-specific parsers and rules sharing a local query,
evidence and evaluation interface. It does not mean identical cloud permission
semantics, or joining identities across providers using a shared email/IP alone.
Additional provider implementations are deferred to the next phase.

| Provider/source | Parser | Fixture validated | Public security dataset validated | Personal live event validated |
|---|---|---|---|---|
| AWS CloudTrail | Implemented | Official samples + synthetic | No | No |
| Azure Activity | Not implemented | No | No | No |
| Entra sign-in/audit | Not implemented | No | No | No |
| GCP Audit Logs | Not implemented | No | No | No |
| Generic endpoint | Not implemented | No | No | No |

Official samples are illustrative vendor examples, not personally generated live
events. Synthetic fixtures contain invented identities, timestamps and event
sequences. No third-party security dataset or employer telemetry is included.
[DATA_SOURCES.md](DATA_SOURCES.md) documents every fixture collection, provenance,
licenses and the public references reserved for later phases.

All analysis runs locally. The runtime has no network client or external LLM
integration; DuckDB external file/network access is disabled. This is a deliberate
design choice for sensitive environments, not a regulatory certification. A
Python-level network-blocking test supplements the architecture; it is not an OS
network sandbox. The optional public-documentation acquisition script is separate
from the runtime. There is no local LLM integration in Phase 1.

## Development checks

```sh
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m ruff check src tests scripts
.venv/bin/python -m ruff format --check src tests scripts
.venv/bin/python -m unittest discover -s tests -v
```

GitHub Actions runs these checks and the CLI walkthrough against a non-editable
installation on Python 3.11 and 3.14. Regression tests compare current AWS results
with the preserved Phase 1 findings and scenario scores, and verify that the
generator still reproduces the original corpus byte for byte.

## Limitations and project status

- The parser supports CloudTrail JSON objects, `Records` wrappers and JSONL. It
  does not support every AWS export envelope, gzip import or all service-specific
  error encodings. It preserves raw data but is not a full vendor-schema validator.
- The rules cover two narrow behaviors. Delayed actions, temporary-credential
  chains, other policy types and missing fields can evade them.
- Successful API records are not proof of effective privilege, persistent state,
  internet reachability, exploitation or malicious intent.
- Synthetic labels express scenario-author intent unavailable to a real analyst.
  There is no external benchmark, production load test or empirical base rate.
- There is no frontend, case-management system, automated response, Sigma adapter,
  cloud collector or LLM. There is no personally generated live-cloud evidence.

[PHASE1_REPORT.md](PHASE1_REPORT.md) records supported claims and completion
evidence. The multicloud milestone is **not complete**: its completion criteria
include additional providers, at least six detections, at least three hunts and
an updated walkthrough and documentation. [OPTIONAL_LIVE_LAB.md](OPTIONAL_LIVE_LAB.md)
describes deferred work and is not a prerequisite. Current implemented scope is AWS.
