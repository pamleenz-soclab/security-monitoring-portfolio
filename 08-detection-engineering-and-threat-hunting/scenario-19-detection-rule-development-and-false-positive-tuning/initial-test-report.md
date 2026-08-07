# Initial Test Report — v1

The Phase 2 broad-rule suite intentionally exposed noise: 17 of 24 expected outcomes passed and seven broad-rule false-positive cases were retained. The purpose was not to build a perfect first rule, but to record why broad logic failed and what type of tuning was required.

Examples included unrelated MFA correlation, legitimate SYSTEM PowerShell scheduled administration, single generic SQLi signatures, approved credential rotation, weak credential joins, and duplicate DNS ingestion inflating thresholds.

Historical results are retained in `evidence/processed/initial-rule-test-results.csv`. They must not be interpreted as production accuracy metrics.
