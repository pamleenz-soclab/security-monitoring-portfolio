# Tuning Decision Record

The final lifecycle uses three versions:

- **v1 broad initial:** intentionally noisy baseline.
- **v2 synthetic-tuned:** reduced the designed synthetic noise but still contained assumptions later challenged by source evidence.
- **v3 source-evidence-informed final candidate:** final Scenario 19 rule semantics.

The most important v3 changes are: R19-01 removes SessionId as a mandatory grouping field; R19-02 adds a suspicious follow-on branch; R19-03 uses multi-rule/specialist transaction evidence or 20 distinct transactions/5m; R19-04 correlates both stable IDs over 24h and keeps approval as enrichment; R19-06 uses exact dedup plus unique chunks and treats completion only as confidence.

See `evidence/processed/tuning-comparison.csv`.
