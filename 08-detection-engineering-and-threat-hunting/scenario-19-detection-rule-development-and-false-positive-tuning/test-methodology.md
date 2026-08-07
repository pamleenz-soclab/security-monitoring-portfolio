# Test Methodology

The local evaluator tests canonical core logic. It does not emulate SIEM parsing, query planners, field extraction, table permissions, late arrival or native null/multivalue semantics.

Test classes include malicious target behaviour, Benign Positive, negative controls, threshold/time boundaries, missing fields, shared infrastructure, duplicate ingestion and out-of-order records. Missing mandatory fields produce `Unable to evaluate`.

Metrics describe the curated fixture suite only. The project does not claim a production false-positive rate, precision, recall or performance benchmark from these fixtures.

Run `bash scripts/safe-reproduce.sh` to execute fixture provenance checks, v3 regression, metrics summary, sanitisation tests, semantic-table validation and portfolio validation.
