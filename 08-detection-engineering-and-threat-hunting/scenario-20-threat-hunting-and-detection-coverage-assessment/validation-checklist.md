# Validation Checklist

## Repository and source safety

- [x] Scenario 01–19 source status unchanged during Stage 2 evaluator run.
- [x] Scenario 01–19 source status unchanged during precision correction.
- [x] Only selected processed evidence was read for formal hunting.
- [x] No other scenario's `evidence/raw/` or `evidence/working/` was copied into final evidence.
- [x] Source processed files read: 39.
- [x] Source-file access failures: 0.

## Hunt integrity

- [x] Eight formal hypotheses have one final outcome each.
- [x] Supported: 5.
- [x] Negative hunt result: 2.
- [x] Unable to assess: 1.
- [x] Negative hunts are preserved separately.
- [x] `Not observed` is not rewritten as `did not occur`.
- [x] `Not available` is not rewritten as `Not observed`.

## Coverage integrity

- [x] Attack-chain, telemetry, and detection matrices use the same 32 behaviour/step rows.
- [x] Confirmed Detection Gaps: 1.
- [x] Logging / Visibility Gaps: 8.
- [x] Existing analytics are not treated as verified production deployment.
- [x] ATT&CK mappings are not converted into a coverage percentage.
- [x] Precision review withdrew HC-01/DG-01 and HC-05/DG-03 as over-broad detection-gap classifications.
- [x] HC-07 was rerun with corrected R19-03 threshold/window semantics.

## Publishing checks still required locally

- [ ] Run `git diff --check`.
- [ ] Confirm `evidence/working/` and `evidence/raw/` are ignored/not staged.
- [ ] Review `git status --short` before commit.
- [ ] Confirm source-scenario licence/provenance records remain available for inherited source datasets.
