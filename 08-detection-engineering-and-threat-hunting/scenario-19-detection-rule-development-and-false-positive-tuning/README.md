# Scenario 19 — Detection Rule Development and False-Positive Tuning

**Priority:** Flagship
**Domain:** Detection Engineering and Threat Hunting
**Status:** Complete portfolio scenario; production deployment not claimed

## Objective

This scenario converts processed investigation evidence from earlier portfolio scenarios into a tested detection-engineering lifecycle rather than investigating a new incident. Six behaviours were selected because their evidence supported explicit requirements, malicious/benign controls, tuning, regression, and cross-platform comparison.

## Detection engineering lifecycle demonstrated

`Requirement -> observable behaviour -> canonical mapping -> v1 broad rule -> fixtures -> test -> FP/FN analysis -> v2 tuning -> source-evidence review -> v3 candidate -> regression -> platform comparison -> deployment/health guidance`

## Final rule set

| Rule | Detection | Main engineering lesson |
|---|---|---|
| R19-01 | MFA denial/timeout -> success | Do not require a correlation field that source failure events do not reliably expose |
| R19-02 | Scheduled task -> SYSTEM PowerShell | Behaviour-chain correlation is stronger than token-only tuning |
| R19-03 | SQLi multi-rule/burst | Count distinct transactions and distinguish high-confidence transactions from generic signature noise |
| R19-04 | Credential add -> SP sign-in | Correlate both stable service-principal and credential identifiers |
| R19-05 | Privileged group addition | Benign Positive is not the same as False Positive |
| R19-06 | Structured DNS chunk transfer | Exact-dedup before thresholds; completion is confidence/outcome evidence, not a mandatory trigger |

## Regression status

The v3 public suite contains **37 pre-declared expected outcomes**: 13 True Positive, 3 Benign Positive, 15 True Negative, and 6 Unable to test. The local canonical evaluator currently matches all 37 expectations.

`tests/expected/expected-results.csv` is the authoritative regression oracle. Fixture-embedded expected labels are duplicate metadata only and are checked against that external oracle before evaluation. This prevents the evaluator from silently treating a fixture's own expected label as the sole source of truth.

The suite is curated and is not an independent enterprise population. Therefore production precision, recall, false-positive rate, performance, query cost, and native Sentinel/Splunk/Elastic/Sigma compatibility are **Not tested**.

## Evidence and implementation boundaries

- Source-derived fixtures use minimal sanitised transformations of processed evidence from Scenarios 11, 12, 15, 16, 17 and 18.
- Raw/working evidence is not copied into Scenario 19.
- Source hashes are anchored to the repository commit recorded in `evidence/processed/source-sha256-records.tsv` when the source path still exists at that commit.
- Platform files under `detections/` are candidate translations or primitives; `evidence/processed/cross-platform-semantic-comparison.csv` records where semantics are aligned, approximate, or incomplete.
- A detection match is not proof of attack success or maliciousness. Approved target behaviour can be a Benign Positive; missing mandatory telemetry is `Unable to evaluate`, not a True Negative.

## Reproduce

```bash
bash scripts/safe-reproduce.sh
```

Start with `tuning-decision-record.md`, `test-methodology.md`, `evidence/processed/tuning-comparison.csv`, and `tests/results/final-v3-test-results.csv`.
