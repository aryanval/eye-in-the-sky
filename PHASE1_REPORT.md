# Phase 1 completion report

**Completed and published: 2026-09-30.** The Phase 1 scope is AWS CloudTrail
ingestion, two SQL detections, one hunt, raw evidence inspection, reproducible
evaluation and a CLI walkthrough. Additional providers are deferred to the next phase.

## Completion criteria

| Criterion | Result | Evidence and boundary |
|---|---|---|
| Local analysis without a cloud account | Passed | Python, DuckDB and SQL; installed runtime and walkthrough use local fixtures. Dependency installation needs a package source. |
| Traceable inputs | Passed | Seven official AWS examples and 24 original synthetic scenarios; both manifests and all 31 source-file hashes verified. [Source inventory](DATA_SOURCES.md) and [notices](THIRD_PARTY_NOTICES.md) retain provenance and upstream terms. |
| CloudTrail ingestion and common model | Passed | JSON objects, `Records` wrappers and JSONL; nullable fields, unknown MFA, duplicate handling, transactional imports and retained raw data. [Architecture](ARCHITECTURE.md) documents the supported mappings. |
| Exactly two AWS detections | Passed | EITS-AWS-001 and EITS-AWS-002 execute multi-event SQL correlations with account/credential joins and a 30-minute window. The restart-aware query is an optional revision of rule 002. [Catalog](DETECTION_CATALOG.md). |
| One executable hunt | Passed | HUNT-001 returns 12 credential leads, retaining unused and unresolvable creations. It finds case-03's 45-minute attachment missed by rule 001. [Hunt](HUNTS.md). |
| Findings resolve to source evidence | Passed | Baseline evaluation verifies 20 supporting events; the candidate verifies 16. The walkthrough resolves record pointers, inspects raw JSON and exports a source file whose SHA-256 matches the retained original. |
| Measured failures and tuning tradeoffs | Passed | Separate labels, preserved baseline/candidate reports, explicit FP/FN counts and unscored ambiguous cases. No fixture label or allowlist enters detection predicates. [Evaluation](EVALUATION.md). |
| Correctness checks | Passed | 25 tests passed at the Phase 1 milestone. No runtime code changed during closeout; the clean installed runtime matches the final workspace byte for byte. |
| Clean installation and walkthrough | Passed | A non-editable wheel installation ran the complete CLI walkthrough; `pip check` found no broken requirements. Packaged Python, SQL and rule metadata match the workspace. |
| Documentation and review | Passed | README, architecture, catalog, hunt, evaluation, provenance, optional-lab boundaries and this report; local Markdown targets and the publication diff reviewed. |
| Public repository | Passed | [aryanval/eye-in-the-sky](https://github.com/aryanval/eye-in-the-sky), branch `main`; implementation commit `3a6e5f5` pushed without force and GitHub visibility verified public. Baseline commit `8179dc1` remains in history. |

## Executed validation

The tested environment is Python **3.14.6**, DuckDB **1.5.6** and pytz **2026.4**.
The package declares Python >=3.11; other Python versions have not been tested.
The earlier 25-test result covers the final parser/manifest changes and candidate
rule. Closeout did not rerun the unchanged test suite.

These commands completed successfully using the clean, non-editable installation:

```sh
work/clean-env/bin/python scripts/demo.py
work/clean-env/bin/python -m pip check
```

The walkthrough ingested 7 official events and 240 unique synthetic events
(247 total). The synthetic input contains 264 records, including 24 duplicate
deliveries and 192 background events. Re-ingestion added zero events. Both
baseline rules together returned **10 findings**; HUNT-001 returned **12 leads**.
The walkthrough also inspected an authorized bootstrap false positive, verified
raw evidence/export, and evaluated both rule revisions.

Its local artifacts are in ignored `work/phase1-demo-0lglqlcs/`. They are
reproducible with [scripts/demo.py](scripts/demo.py); they are not committed
databases or additional source datasets. A normal checkout can follow the
[README commands](README.md) to create its own environment and artifacts.

The clean-install reports were **byte-for-byte identical** to the saved final
reports below. Their recorded runtime-code, executed-SQL, input-manifest and
ground-truth hashes were checked against the current files. All installed Python,
SQL and rule-metadata files were also compared with the source tree.

| Retained final report | SHA-256 |
|---|---|
| [Baseline](evaluation/phase1-baseline.json) | `199302289a73e846477c8d830f219ccbd41a919f1b10cf3846aaf05cf0050a2d` |
| [Restart-aware](evaluation/phase1-restart-aware.json) | `fe134db14bedcda58c5bdd3d427d5de25e238b8e3a9fcb6eabfe71ca5e13b84e` |

Earlier development and full-corpus snapshots remain unchanged. The original
development baseline and implementation are retained in commit `8179dc1`.

## Measured results and decision

These results describe the authored synthetic corpus, not production performance.
Each rule has six malicious, four benign and two ambiguous scenarios. Missing
telemetry remains a false negative when the fictional scenario is malicious.

| Rule / revision | TP | FP | FN | TN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| EITS-AWS-001 v1.0.0 | 2 | 1 | 4 | 3 | 66.7% | 33.3% |
| EITS-AWS-002 v1.0.0 baseline | 3 | 2 | 3 | 2 | 60.0% | 50.0% |
| EITS-AWS-002 v1.1.0 restart-aware | 2 | 1 | 4 | 3 | 66.7% | 33.3% |

Each row also has two ambiguous scenarios, one alerting; these are excluded from
precision and recall. Baseline produces ten findings including the two unscored
alerts. Selecting the candidate produces eight findings and leaves rule 001
unchanged. Neither revision produces duplicate or unassigned findings on this
corpus.

**Baseline remains the default.** The candidate suppresses an intervening
successful `StartLogging` for the same account/trail. That changes authorized
maintenance case-19 from FP to TN, but malicious case-16 from TP to FN. Restoring
logging does not establish benign intent. Authorized bootstrap case-06 and
emergency-access case-18 remain legitimate lookalike false positives.

Rule 001 still misses delayed use, STS credential transitions and missing
telemetry. Rule 002 still misses delayed ingress and absent stop/permission data.
The [per-scenario analysis](EVALUATION.md) records these failures. Development and
holdout partitions are authored diagnostic variants, not an independent blinded
benchmark; the first development report also retained full-corpus findings.

## Supported claims

| Claim | Supported? | Evidence | Limitation |
|---|---|---|---|
| Built AWS telemetry ingestion | Yes | Seven official fixtures, parser checks and walkthrough | Limited CloudTrail formats; no live validation |
| Built multicloud telemetry ingestion | No | Future public source inventory only | Azure, Entra and GCP parsers are not implemented |
| Authored cloud detections | Yes | Two executed SQL rules and preserved reports | AWS only; narrow behaviors |
| Performed threat hunts | Yes | HUNT-001 and 12 fixture leads | One hunt using fixture data |
| Used SQL security correlation | Yes | Two sequence rules and the hunt | Local batch analysis |
| Measured false positives and false negatives | Yes | Scenario-level evaluation and candidate comparison | Small synthetic corpus with author-defined intent |
| Investigated AWS CloudTrail format | Yes | Official examples and independent parser assertions | Does not establish production AWS experience |
| Investigated Azure Activity and Entra | Documentation only | Public references in DATA_SOURCES.md | No executable parser validation |
| Investigated GCP Audit Logs | Documentation only | Public references in DATA_SOURCES.md | No executable parser validation |
| Hands-on AWS validation | No | No personal live events | Official samples and synthetic data only |
| Hands-on Azure validation in this project | No | No personal live events | Documentation only |
| Hands-on GCP validation | No | No personal live events | Documentation only |
| Built local evidence inspection | Yes | CLI explanations, retained source bytes and verified export | No durable case-management UI |
| Phase 1 complete and published | Yes | Completion criteria, exact replay and public repository above | AWS scope only |
| Multicloud milestone complete | No | Additional provider implementations remain deferred | Requires more providers, at least six detections, at least three hunts and an updated walkthrough and documentation |

## Remaining boundaries

No employer/customer material was used. Official samples retain their vendor
attribution and license terms; original implementation and synthetic fixtures
use the project's MIT license. Source categories distinguish vendor examples
from fictional sequences, public datasets and personally generated events.

Successful API records cannot establish effective privilege, lasting state,
internet reachability, exploitation, intent or authorization. Evidence hashes
demonstrate consistency with retained bytes, not independent authenticity.
There is no production load validation or external security benchmark.

Runtime analysis uses no network client and disables DuckDB external I/O. The
Python network-blocking test is not an operating-system sandbox or a regulatory
certification. The optional documentation fetcher is separate from normal use.

**Current scope is AWS CloudTrail.** Azure/Entra/GCP/endpoint ingestion, Sigma, UI,
LLM/Ollama, infrastructure and optional live accounts remain deferred. The
[optional live lab](OPTIONAL_LIVE_LAB.md) remains deferred and unexecuted.
