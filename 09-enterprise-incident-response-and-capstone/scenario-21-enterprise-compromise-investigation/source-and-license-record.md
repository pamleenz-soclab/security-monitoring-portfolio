# Source and License Record

## Source

Primary upstream repository: OTRF `detection-hackathon-apt29`
Pinned commit: `b5989e17465753f46433e77f795f651453c01279`
Primary investigation scope: Day 1 only.

The authoritative acquisition ledger is:

- `evidence/processed/source-acquisition-manifest.tsv` — upstream artifact path, byte size, SHA-256, pinned commit, source URL, and investigation role.
- `evidence/processed/dataset-boundary-record.tsv` — case boundary, source/working policies, host archive size, extracted host JSON size, and local working-path convention.

The published package retains the SHA-256 of the **upstream host archive**. It records the extracted host JSON size and working path but does not claim that an extracted-JSON SHA-256 is published.

## License boundary

A repository-level GNU GPL v3 LICENSE was observed and hashed during acquisition. A separate dataset-specific licensing statement was not independently established in the reviewed Day 1 metadata.

The public portfolio therefore does **not redistribute upstream raw telemetry**. Raw archives and extracted raw/working evidence remain local and Git-ignored. The repository publishes provenance records, derived/sanitized evidence, methodology, and analysis.
