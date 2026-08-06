# Scripts

- `acquire-dataset.sh` — downloads and verifies the official archive.
- `safe_extract_zip.py` — rejects unsafe ZIP members before extraction.
- `parse_modsec_audit.py` — first-pass native ModSecurity parser.
- `run-first-pass.sh` — extraction and first-pass orchestration.
- `precise_validate.py` — representative transaction and action-marker validation.
- `run-precise-validation.sh` — precise-validation wrapper.
- `build_processed_evidence.py` — creates bounded publishable evidence from working output.
- `portfolio_validator.py` — verifies package completeness, sanitisation and Git boundaries.
- `reproduce-safe.sh` — safe offline end-to-end wrapper.

The scripts do not connect to or test any target. The only network operation is the optional download of the published dataset.
