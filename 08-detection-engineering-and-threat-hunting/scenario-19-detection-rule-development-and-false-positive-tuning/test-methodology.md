# Test Methodology

The local evaluator tests canonical core logic. It does not emulate SIEM parsing, query planners, field extraction, table permissions, late arrival, scheduling, or native null/multivalue semantics.

The authoritative expected outcomes are stored separately in `tests/expected/expected-results.csv`. `scripts/fixture-building/build_fixtures.py` checks one-to-one fixture/oracle/ground-truth identity and rejects expected-label drift before the evaluator runs. `scripts/evaluation/test_runner.py` compares evaluator output to that external oracle and writes `tests/results/final-v3-test-results.csv` with LF line endings for stable Git reproduction.

Test classes include malicious target behaviour, Benign Positive, negative controls, threshold/time boundaries, missing fields, shared infrastructure, duplicate ingestion and out-of-order records. Missing mandatory telemetry produces `Unable to evaluate` when the rule cannot establish its required semantics.

Metrics describe the curated fixture suite only. The project does not claim a production false-positive rate, precision, recall or performance benchmark from these fixtures.

Run `bash scripts/safe-reproduce.sh` to execute fixture/oracle provenance checks, v3 regression, metrics summary, sanitisation, semantic-table validation, portfolio validation and Git-aware evidence checks.
