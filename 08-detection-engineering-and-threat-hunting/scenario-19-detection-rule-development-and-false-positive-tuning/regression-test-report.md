# Regression Test Report — v3

The final public regression suite is executed by `scripts/evaluation/test_runner.py`. It includes synthetic and sanitised-derived cases for all six rules, including missing-field, duplicate-ingestion, out-of-order, boundary and Benign Positive cases.

A passing regression means the local canonical evaluator produced the pre-declared expected outcome for each fixture. It does not mean the rule has been natively executed in Sentinel, Splunk, Elastic or Sigma tooling.

See `tests/results/final-v3-test-results.csv` and `evidence/processed/detection-metrics.csv`.
