# Scripts

- `acquire-dataset.sh` — downloads and verifies the official archive.
- `safe_extract_zip.py` — rejects unsafe ZIP members before extraction.
- `parse_modsec_audit.py` — first-pass native ModSecurity parser.
- `run-first-pass.sh` — extraction and first-pass orchestration.
- `precise_validate.py` — representative transaction and action-marker validation.
- `run-precise-validation.sh` — precise-validation wrapper.
- `build_reproduction_sample.py` — creates a bounded local sample under Git-ignored `evidence/working/reproduced/` to verify the analytical workflow.
- `portfolio_validator.py` — validates required portfolio files, sanitisation boundaries and Git handling.
- `reproduce-safe.sh` — safe offline orchestration wrapper; it does not send traffic to a target.

The only network operation is the optional download of the published dataset. The reproduction workflow does not overwrite the curated evidence in `evidence/processed/`.
