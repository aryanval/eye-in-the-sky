# Phase 2 implementation and validation report

The implementation adds four source adapters, four detections and two hunts to
the reviewed architecture at `4a44570`. The project now has **five telemetry
sources, six detections and three hunts**. Live account validation is **NO** for
every source. Validation uses public vendor schemas/examples and independently
generated synthetic fixtures, without cloud accounts, credentials or API access.

**Validation status:** 108 tests, dependency checks, lint, formatting and the
multicloud CLI walkthrough pass from a fresh non-editable Python 3.14.6
installation. GitHub Actions results are pending before milestone completion.

## Provider and source coverage

| Provider/source | Parser implemented? | Complete official fixture validated? | Synthetic corpus validated? | Detection count | Hunt count | FP/FN measured? | Live account validated? |
|---|---|---|---|---:|---:|---|---|
| AWS CloudTrail | YES | YES, 7 unchanged events | YES, 24 scenarios / 240 unique events | 2 | 1 | YES | **NO** |
| Azure Activity REST EventData | YES | YES, 1 unchanged event | YES, 17 scenarios / 84 events | 1 | 0 | YES | **NO** |
| Entra Graph v1.0 sign-ins | YES | NO; abbreviated documentation excerpt retained | YES, 13 hunt records | 0 | 1 | N/A; exploratory hunt | **NO** |
| Entra Graph v1.0 directory audits | YES | NO; abbreviated documentation excerpt retained | YES, 18 scenarios / 69 events | 1 | 0 | YES | **NO** |
| GCP Cloud Audit LogEntry | YES | NO; abbreviated documentation excerpts retained | YES, 30 scenarios / 73 events | 2 | 1 | YES | **NO** |

The combined store contains 487 unique events, including 8 complete official
example events. It produces 30 baseline findings. HUNT-001/002/003 return 12/5/14
exploratory leads. Official examples are not live observations. Abbreviated or
invalid vendor examples remain unchanged documentation evidence; executable
synthetic records are generated separately, with transformations and usage
recorded in [DATA_SOURCES.md](DATA_SOURCES.md) and the per-source documents.

## Detections and observed evaluation

The new Azure Activity, Entra audit and GCP key rules correlate two ordered events.
The GCP bucket-policy rule uses one event and retains every qualifying delta.
Thus **three of the four new rules are multi-event correlations**. All six rules
have malicious, benign, ambiguous and missing-telemetry scenarios plus noise;
ground truth remains outside detector input.

| Rule | TP | FP | FN | TN | Precision | Recall | Complete-telemetry recall | Ambiguous alerts / cases |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| EITS-AWS-001 | 2 | 1 | 4 | 3 | 66.7% | 33.3% | 50.0% | 1 / 2 |
| EITS-AWS-002 | 3 | 2 | 3 | 2 | 60.0% | 50.0% | 75.0% | 1 / 2 |
| EITS-AZURE-001 | 2 | 2 | 7 | 5 | 50.0% | 22.2% | 40.0% | 1 / 1 |
| EITS-ENTRA-001 | 3 | 2 | 6 | 5 | 60.0% | 33.3% | 75.0% | 1 / 2 |
| EITS-GCP-001 | 2 | 1 | 6 | 5 | 66.7% | 25.0% | 40.0% | 1 / 1 |
| EITS-GCP-002 | 2 | 2 | 5 | 5 | 50.0% | 28.6% | 66.7% | 1 / 1 |

These are synthetic-corpus results, not production effectiveness estimates.
Ambiguous alerts are separately reported and excluded from precision/recall.
Complete-telemetry recall supplements overall recall; missing telemetry remains
visible in the primary score. Exact anchor sets, including omitted expected
records, prevent unrelated or partial evidence from earning a true positive.

The AWS restart-aware candidate remains preserved: EITS-AWS-002 changes to
TP=2, FP=1, FN=4, TN=3, precision=66.7%, recall=33.3%, complete recall=50.0%.
It removes one maintenance FP and loses one malicious TP; baseline remains the
default. No Phase 2 label-driven tuning or hidden candidate was applied.
[EVALUATION.md](EVALUATION.md) links all five new replay reports and separate truth.

Each new [rule design](DETECTION_CATALOG.md#phase-2-detections) records exact public
fields, relevance, benign workflows and what telemetry cannot establish, along
with SQL, ATT&CK behavior mapping, metadata and limitations. [HUNTS.md](HUNTS.md)
links all three hypotheses, queries and investigation guidance.

## Implementation and validation evidence

- [Adapters](src/eits/adapters/) implement five source formats through the existing
  manifest/parse/normalize/store interface, preserving raw events and provider
  extensions. [Source documents](DATA_SOURCES.md) state exact scope mappings.
- [Azure tests](tests/test_azure_activity.py), [Entra tests](tests/test_entra.py)
  and [GCP tests](tests/test_gcp.py) cover normal and missing/null fields, outcomes,
  supported envelopes, provider/tenant/scope isolation, source conflicts,
  exact evidence, benign lookalikes, telemetry gaps and timestamp boundaries.
- [Multicloud integration](tests/test_multicloud.py) imports all seven manifests,
  runs six rules and three hunts under a Python network blocker, resolves every
  finding and hunt UID, compares AWS findings/scores with the frozen report, and
  byte-reproduces all three new synthetic generators and separate labels.
- [Generic rule tests](tests/test_rules.py) validate 1..N supporting events and
  exact-set scoring. [AWS regression tests](tests/test_regression.py) preserve
  original report bytes, generated fixtures, findings and scores. Migration tests
  continue to verify the existing additive v1-to-v2 migration and rollback.
- [CLI demo](scripts/demo.py) ingests every source, demonstrates findings from each
  provider family, verifies raw exports, runs three hunts, opens an authorized
  false positive and reports metrics for every rule plus the AWS candidate.
- [CI](.github/workflows/ci.yml) retains Python 3.11/3.14, dependency checks, lint,
  format checks, unit/integration tests and the updated multicloud walkthrough.
  It installs the distributable package without editable source imports.

## Schema and exact compatibility effects

**No Phase 2 schema migration.** Database version remains 2. The existing v1-to-v2
migration from the architecture refactor remains unchanged. No core ingestion,
Event identity, conflict engine, query wrapper or evidence-engine redesign was
needed. New parser details and fractional timestamp remainders use extensions.

- Original AWS parser, fixtures, truth, SQL/hunt and preserved evaluation reports
  remain byte-identical. AWS event/finding IDs, input/query hashes, observed
  findings, scores and hunt results are unchanged, including in the mixed store.
- Other sources use the already-reviewed v2 provider/source/typed-scope UID.
  GCP source IDs combine insertId with original timestamp text in the log-owning
  scope. Absent scope retains conservative source-conflict behavior. No email,
  username, IP or display name establishes cross-cloud identity equivalence.
- Evaluation selects rules by the manifest provider/source. Bare `evaluate`
  still selects AWS and returns exactly its two rules. Report schema remains 2;
  new package code/resource/registry hashes truthfully differ from old reports.
- Bare `detect` now has six registered rules; an AWS-only database retains its
  original outputs. Bare `hunt` still defaults to HUNT-001; the new hunts are
  selected with `--hunt-id`. `status` reports phase 2 and all five source adapters.
- Package version is 0.2.0. `scripts/demo.py` becomes the multicloud walkthrough;
  `scripts/demo_phase1.py` retains the AWS walkthrough and results. No historical
  report or git history is rewritten.

## Changed files

New source modules are `adapters/azure_activity.py`, `adapters/entra.py` and
`adapters/gcp.py`. New SQL comprises EITS-AZURE-001, EITS-ENTRA-001, EITS-GCP-001,
EITS-GCP-002, HUNT-002 and HUNT-003. New rule/hunt metadata and registry entries
activate them. Four new test modules cover providers and the combined workflow.

New `fixtures/azure/` and `fixtures/gcp/` contain provenance, retained vendor
material and independently generated data; three generator scripts produce
separate truth files. Five `evaluation/phase2-*.json` reports preserve the measured
results. `docs/sources/`, `docs/detections/` and `docs/hunts/` record exact contracts.

Shared edits are adapter registration, source-filtered evaluation/registry,
CLI status, package version/description, the walkthrough, the migration/catalog
test expectations and the CI walkthrough step name. Public README, architecture,
source/notices/license, detection/hunt/evaluation and milestone documents now
reflect this scope. No internal workflow instructions are introduced.

## Claim assessment

The implementation/test evidence supports each technical clause of:

> Built a local multicloud detection & threat-hunting platform across AWS CloudTrail, Azure Activity/Entra and GCP Audit Logs; authored and evaluated detections, correlated attack sequences and measured FP/FN behavior with evidence-backed findings.

| Clause | Supported? | Implementation and test evidence | Boundary |
|---|---|---|---|
| Built a local multicloud detection & threat-hunting platform | YES | Shared DuckDB/CLI engine; [offline combined integration](tests/test_multicloud.py), [demo](scripts/demo.py), [three hunts](HUNTS.md) | Local batch investigation, not production multicloud administration |
| Across AWS CloudTrail, Azure Activity/Entra and GCP Audit Logs | YES | [Five registered adapters](src/eits/adapters/__init__.py), provider tests above and retained/synthetic source inventory | Explicit representations only; Graph/GCP official excerpts are incomplete; no live validation |
| Authored and evaluated detections | YES | [Six SQL rules and metadata](DETECTION_CATALOG.md), [evaluation reports](EVALUATION.md) and exact-score tests | Small author-defined synthetic corpus, not an external benchmark |
| Correlated attack sequences | YES | Five ordered sequence rules, malicious/benign/ambiguous scenarios and boundary/scope tests | Correlates recorded behavior in fictional attack scenarios; cannot establish intent, causality, credential use or privilege beyond each rule's fields |
| Measured FP/FN behavior with evidence-backed findings | YES | Separate labels, exact-anchor scoring, [generic tests](tests/test_rules.py), every-finding resolution and raw export checks | Hash consistency is not independent source authenticity; synthetic metrics are not population estimates |

The wording is defensible with the public fixture-only validation boundaries
above. “Multicloud” means telemetry formats share investigation, detection, hunt,
evidence and evaluation interfaces. It does not mean unified enterprise identity
or cross-cloud causal attribution. Recorded administrative success cannot prove
effective privilege, public reachability, persistent state or malicious intent.

No frontend, LLM, endpoint/EDR, cloud account, live collection or infrastructure
deployment is included. Those remain outside this milestone.
