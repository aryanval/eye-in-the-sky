# Resume work — Eye in the Sky

**Resumed from the 2026-09-30 handoff. Phase 1 implementation and validation are
complete, and PHASE1_REPORT.md is written. Publication is the final remaining
step. Phase 2 and later phases are not approved.**

## Workspace and authorization

- Repository: `/Volumes/500GB SSD/Dev/eye-in-the-sky` (renamed from `third-eye`).
- Remote: `https://github.com/aryanval/eye-in-the-sky.git`, configured as `origin`.
- GitHub was checked and is currently **private**, initially empty. Nothing has
  been pushed during this work. The original objective is a public project.
- Local branch: `main`. Initial baseline commit: `8179dc1`.
- Later implementation changes, reports and documentation remain uncommitted.
- The workspace and writable root now use `eye-in-the-sky`. Do not recreate the
  old `third-eye` folder.
- Phase 1 implementation is approved. Phase 2 and later phases are not approved.
- Public documentation and non-employer material may be read. Never inspect or
  reuse employer/customer data, code, prompts, schemas, architecture, detections,
  workflows or remembered incident sequences. No such material has been used.

## Scope to preserve

Python + DuckDB + SQL + CLI. Exactly two AWS detections, one AWS hunt, provenance,
raw evidence tracing, evaluation and a CLI walkthrough. No account requirement.
Azure/Entra/GCP/endpoint ingestion, Sigma, UI, Ollama and infrastructure remain out
of scope. Documentation links for future cloud sources are research only.

## Implemented

- Package in `src/eits/`, with commands `ingest`, `status`, `detect`, `explain`,
  `event`, `hunt`, `export-raw`, and `evaluate`.
- Pinned runtime dependencies: DuckDB 1.5.6, pytz 2026.4. Python 3.14.6 was used.
  `pyproject.toml` declares Python >=3.11, but other Python versions are untested.
- CloudTrail objects, `Records` wrappers and JSONL; nullable common fields and
  preserved cloud-specific/raw data. Missing MFA is unknown, not false.
- Mandatory provenance manifests, hash verification, transactional imports,
  duplicate handling, path confinement and rejection of conflicting source IDs.
- Original source bytes retained inside DuckDB. Evidence inspection re-hashes
  those bytes and resolves the exact record. Raw export is byte-for-byte.
- EITS-AWS-001: successful new key used directly for AdministratorAccess attachment
  in the same account, with exact key matching and 0 < elapsed <=30 minutes.
- EITS-AWS-002 baseline: successful StopLogging followed by public SSH/RDP-capable
  ingress, matching account/principal/credential, same time window. Public CIDR
  and port/protocol must occur in the same permission entry; IPv6 is supported.
- Separate opt-in `restart-aware` candidate, rule 002 version 1.1.0. It suppresses
  pairs with an intervening successful exact-account/trail StartLogging.
  **Baseline remains the default because the candidate loses malicious coverage.**
- HUNT-001: first 24 hours of newly created credential use, retaining unused and
  unresolvable creations. It reveals a delayed attachment missed by rule 001.
- Deterministic synthetic generator, separate ground-truth labels, preserved
  baseline/candidate reports, readable predicates and explicit observed/inferred/
  unresolved evidence sections. The runtime has no network client; DuckDB external
  I/O is disabled.

## Data and measured results

- `fixtures/aws/official/`: seven official AWS documentation examples with source
  URL, retrieval/page/file hashes and license attribution. No event values changed.
- `fixtures/aws/synthetic/`: 24 original scenarios, 264 records including 24
  duplicate deliveries, 240 unique events and 192 background events.
- `evaluation/ground_truth.json` is separate from detector input. Labels represent
  fictional scenario intent, not facts available in the logs.

| Rule / revision | TP | FP | FN | TN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| EITS-AWS-001 baseline | 2 | 1 | 4 | 3 | 66.7% | 33.3% |
| EITS-AWS-002 baseline | 3 | 2 | 3 | 2 | 60.0% | 50.0% |
| EITS-AWS-002 restart-aware | 2 | 1 | 4 | 3 | 66.7% | 33.3% |

Each rule also has two ambiguous cases, one alerting, excluded from precision and
recall. Missing-telemetry malicious cases remain FN. These are fixture-specific
metrics, not production estimates. The candidate changes benign case-19 from FP
to TN and malicious case-16 from TP to FN. Authorized bootstrap case-06 and
emergency-access case-18 remain legitimate lookalike false positives.

Original development results are in `evaluation/baselines/development-v1.json`
and preserved in commit `8179dc1`. Additional snapshots include
`evaluation/baselines/all-v1.json`, `evaluation/development-restart-aware.json`,
and `evaluation/all-restart-aware.json`. Final-code replays were successfully
written to `evaluation/phase1-baseline.json` and
`evaluation/phase1-restart-aware.json`. Do not overwrite earlier results.

The first development report scored only development cases but retained full-corpus
findings. The documentation explicitly disclaims a blinded/independent holdout.

## Executable validation completed

- `tests/test_phase1.py`: **25 tests passed** after the latest parser/manifest and
  tuning changes. Covers official examples, unknowns, evidence integrity,
  rollback, duplicates, correlation boundaries, IPv6, scoring and offline behavior.
- `scripts/demo.py` successfully ran the complete CLI loop: 7 official +240
  synthetic unique events, 10 baseline findings, 12 hunt leads, raw evidence
  verification/export, benign lookalike and baseline/candidate comparison.
- That walkthrough's artifacts are in ignored `work/phase1-demo-uy_dxhtu/`.
- A clean, non-editable installation **succeeded** in `work/clean-env/`, including
  both pinned dependencies and a built wheel. Its full walkthrough now passed;
  artifacts are in ignored `work/phase1-demo-0lglqlcs/`. `pip check` found no broken
  requirements.
- The installed Python, SQL and rule metadata match the current source tree.
  Clean-install baseline/candidate reports match both final saved reports byte
  for byte. Runtime-code, SQL, input-manifest, ground-truth and fixture-file hashes
  were verified. No runtime code changed during closeout, so the unchanged 25-test
  suite was not rerun.

## Documentation state

Written: `README.md`, `ARCHITECTURE.md`, `DETECTION_CATALOG.md`, `HUNTS.md`,
`EVALUATION.md`, `DATA_SOURCES.md`, `OPTIONAL_LIVE_LAB.md`, `LICENSE`, and
`THIRD_PARTY_NOTICES.md`.

Written during closeout: [PHASE1_REPORT.md](PHASE1_REPORT.md), including completion
gates, exact report hashes, validation commands, measured results and claim limits.
Publication remains pending. Review documentation links and the staged diff before
publication. Official fixtures retain their AWS documentation license; the
project's MIT license does not replace it.

## Current claim boundary

| Claim | Supported? | Evidence | Limitation |
|---|---|---|---|
| Built AWS telemetry ingestion | Yes | Seven official fixtures, parser tests, walkthrough | Limited CloudTrail formats; no live validation |
| Built multicloud telemetry ingestion | No | Future public source inventory only | Azure/Entra/GCP not implemented |
| Authored cloud detections | Yes | Two executed SQL rules and reports | AWS only; narrow behaviors |
| Performed threat hunts | Yes | HUNT-001 and 12 fixture leads | One hunt; fixture data |
| Used SQL security correlation | Yes | Both sequence rules and hunt | Batch local analysis |
| Measured FP/FN | Yes | Preserved scenario reports | Synthetic author-defined corpus |
| Investigated AWS CloudTrail format | Yes | Official examples and independent parser assertions | Not production AWS experience |
| Investigated Azure Activity/Entra | Documentation only | DATA_SOURCES links | No executable parser validation |
| Investigated GCP Audit Logs | Documentation only | DATA_SOURCES links | No executable parser validation |
| Hands-on AWS validation | No | None | No personal live events |
| Hands-on Azure validation in project | No | None | Professional experience is separate |
| Hands-on GCP validation | No | None | No personal live events |
| Built local evidence inspection | Yes | CLI explanation, retained bytes, verified export | No durable case-management UI |
| Phase 1 fully closed/published | Not yet | Implementation, clean-install validation and final report complete | Publication remains |
| Full project resume-ready | No | Later gates unmet | Requires more providers, detections, hunts and later demo |

## Remaining publication closeout

1. Work exclusively in the renamed repository and inspect its Git status; preserve
   any intervening user changes. Do not re-read employer directories.
2. Clean-install walkthrough, dependency check, report hashes/metrics and
   `PHASE1_REPORT.md` are complete. Finish documentation-link/staged-diff review.
   The 25 tests already passed; rerun only if code changes or a failure merits it.
3. Preserve all earlier evaluation reports. Runtime and fixture files did not
   change during this closeout.
4. Commit only the new project changes; `.venv/`, `work/`, databases, build output
   and egg-info are ignored. The initial commit used `aryanval` and
   `aryanval@users.noreply.github.com`, explicitly avoiding a global work identity.
5. Check the provided remote before pushing; never force-overwrite unexpected
   remote work. Publish the reviewed Phase 1 project to the supplied repository
   and set the requested public visibility, unless the user changes that direction.
   These operations have not happened yet.
6. Report Phase 1 results and stop. Do not start Phase 2, optional accounts, UI,
   endpoint support or LLM work automatically. Do not recommend the full target
   resume claim yet.
