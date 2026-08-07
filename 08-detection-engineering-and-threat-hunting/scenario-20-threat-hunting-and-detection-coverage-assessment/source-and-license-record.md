# Source and License Record

## Scenario 20 data provenance

Scenario 20 introduced **no new external raw dataset**. It reused processed evidence and published detection/query artifacts already present in the portfolio.

Formal hunting read **39 processed source files** from Scenarios 10, 11, 13, 15, 16, 17, 18, and 19.

The exact source-file hashes and read status are recorded in:

- `evidence/processed/source-sha256-records.tsv`
- `evidence/processed/hunt-source-access-log.csv`

## Licence handling

Scenario 20 does not re-license or redistribute another scenario's raw dataset. Dataset/source licensing remains inherited from, and should be verified against, the corresponding source scenario's source/licence documentation.

Final public evidence contains derived processed tables and sanitised excerpts only.

## Privacy and sanitisation

No raw cross-scenario evidence is copied into this scenario. `sanitised-hunt-excerpts.tsv` is derived from already processed/sanitised hunt results and retains only the fields needed to support the findings.
