# Evaluation — observed Phase 1 results

Metrics below come from executable SQL against the committed synthetic corpus.
They are not estimates of production detection performance. No precision/recall
target was used as a completion gate; correct execution, defensible scoring and
visible limitations are the gates.

## Corpus and independent labels

[ground_truth.json](evaluation/ground_truth.json) contains 24 scenario narratives
and labels, physically separate from [telemetry](fixtures/aws/synthetic/).
Each rule has 12 scenarios: four malicious with complete telemetry, four benign,
two ambiguous, and two known malicious with deliberately missing telemetry.
The generator also adds 192 background events, 24 duplicate deliveries and a
deterministic shuffled arrival order: 264 input records, 240 distinct events.

Labels describe the fictional scenario's intended authorization/intent. They are
not assertions a detector can recover from otherwise identical log fields. The
detector never reads them. The evaluator matches findings back to expected event
anchors; an unrelated alert in a malicious scenario is not a true positive.

Each rule has six development and six held-out scenario variants, selected before
tuning. These are author-created diagnostic partitions, not an independently
blinded benchmark. The first development report scored only development cases
but retained full-corpus findings; it must not be represented as a blinded trial.

## Definitions

The primary unit is a rule/scenario alert opportunity, not an individual log line.

- TP: a malicious scenario has a finding containing its exact expected event pair.
- FN: a malicious scenario has no correctly evidenced finding, including missing
  telemetry, timing-window and unsupported-credential-path misses.
- FP: a benign scenario alerts. Wrong-evidence findings in malicious scenarios
  also count as FP while the missed scenario remains FN. Unassigned/cross-scenario
  findings are counted separately as FP candidates, not discarded.
- TN: a benign scenario has no finding. Ambiguous scenarios are reported as
  unscored alert/no-alert and excluded from precision/recall.
- Duplicate findings within an opportunity cannot inflate TP; duplicates are
  counted separately. Distinct public permissions in one event pair are grouped.

Precision = TP / (TP + FP). Recall = TP / (TP + FN). A zero denominator yields
`null`, not an invented perfect score. Complete-telemetry recall is an additional
view, never a replacement for the overall result. It still includes timing and
credential-chain misses when the scenario's supplied telemetry is complete.

## Baseline and candidate

| Rule / revision | TP | FP | FN | TN | Precision | Overall recall | Complete-telemetry recall |
|---|---:|---:|---:|---:|---:|---:|---:|
| EITS-AWS-001 v1.0.0 | 2 | 1 | 4 | 3 | 66.7% | 33.3% | 50.0% |
| EITS-AWS-002 v1.0.0 | 3 | 2 | 3 | 2 | 60.0% | 50.0% | 75.0% |
| EITS-AWS-002 v1.1.0 restart-aware | 2 | 1 | 4 | 3 | 66.7% | 33.3% | 50.0% |

Each rule/revision also has two ambiguous cases, one of which alerts. The
baseline produces ten findings including these two unscored alerts. The candidate
produces eight. EITS-AWS-001 is unchanged by selecting the candidate revision.

## What failed and what changed

EITS-AWS-001 misses delayed use (case-03), an STS transition (case-04), an omitted
issued-key response (case-11), and a dropped attachment event (case-12). Case-06's
authorized bootstrap remains a false positive. Changing a scenario label or
allowlisting its fictional actor would not demonstrate better detection logic.

For EITS-AWS-002, the original development result had TP=1, FP=2, FN=2. Inspection
of case-19 exposed a recorded successful `StartLogging` before an approved RDP
change. A separate candidate adds an exact-account/trail restart exclusion.
Development FP falls from two to one, with TP/FN unchanged in that partition.

The full comparison exposes the tradeoff: case-16 is malicious even though the
actor restores logging before changing ingress. It changes from TP to FN under
the candidate. Case-19 changes from FP to TN. The candidate therefore improves
fixture precision but reduces overall recall from 50.0% to 33.3%.

**Decision: retain baseline as default; keep the candidate for comparison.**
A successful restart is counterevidence about logging state, not proof of benign
intent. Case-18's authorized emergency access remains indistinguishable from
unauthorized behavior on the available fields. Delayed ingress (case-15), a
dropped stop event (case-23), and missing permission details (case-24) remain misses.

## Preserved evidence and reproduction

- [Initial development baseline](evaluation/baselines/development-v1.json),
  preserved with the original implementation in commit `8179dc1`.
- [Development candidate](evaluation/development-restart-aware.json).
- [Full baseline snapshot](evaluation/baselines/all-v1.json) and
  [full candidate snapshot](evaluation/all-restart-aware.json).
- Final Phase 1 replays are saved as `evaluation/phase1-baseline.json` and
  `evaluation/phase1-restart-aware.json`; earlier snapshots remain intact.

Reports contain per-scenario results, evidence IDs, input/ground-truth hashes,
executed SQL hashes, runtime-code hashes and Python/DuckDB versions. Each report
describes the code that produced it. Later parser/manifest validation changes do
not rewrite previous reports. Git and the retained baseline SQL preserve history.

```sh
.venv/bin/python -m eits evaluate --split development
.venv/bin/python -m eits evaluate --split holdout
.venv/bin/python -m eits evaluate --revision restart-aware --split holdout
.venv/bin/python -m eits evaluate --output work/new-baseline-report.json
.venv/bin/python -m eits evaluate --revision restart-aware --output work/new-candidate-report.json
```

Output paths must be new. The evaluator uses its own in-memory database and does
not depend on a prior demo or an analyst's working database. It verifies the raw
references of every emitted finding before returning the report.

## Correctness checks and limits

The test suite validates official sample projections, missing/unknown values,
timezone handling, ingestion rollback, provenance hashes, path confinement,
conflicting event IDs, raw-byte survival, duplicate delivery, ordering and time
boundaries, credential/account joins, IPv6, same-permission matching, failures,
restart suppression, hunt behavior and scoring. Runtime functions also run under
a Python network-connection blocker; DuckDB external I/O is disabled.

The small corpus cannot establish population precision, confidence bounds,
throughput, complete ATT&CK coverage or production suitability. Repeated noise
does not create new independent attack trials. Official AWS examples test parsing;
they are not counted as synthetic malicious/benign evaluation scenarios.
