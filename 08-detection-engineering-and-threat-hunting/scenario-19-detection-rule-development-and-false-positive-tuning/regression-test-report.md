# Regression Test Report — v3

The final public regression suite is executed by `scripts/evaluation/test_runner.py`. It includes synthetic and sanitised-derived cases for all six rules, including missing-field, duplicate-ingestion, out-of-order, boundary and Benign Positive cases.

Expected outcomes come from the independent file `tests/expected/expected-results.csv`; fixture-embedded expected labels are validated as duplicate metadata rather than trusted as the sole oracle.

A passing regression means the local canonical evaluator produced the pre-declared expected outcome for each fixture. It does not mean the rule has been natively executed in Sentinel, Splunk, Elastic or Sigma tooling, and it does not establish production precision/recall.

See `tests/results/final-v3-test-results.csv` and `evidence/processed/detection-metrics.csv`.
