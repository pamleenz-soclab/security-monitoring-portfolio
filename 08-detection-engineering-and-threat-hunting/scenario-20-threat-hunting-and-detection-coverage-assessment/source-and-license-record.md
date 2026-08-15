# Source and License Record

## Scenario 20 provenance

Scenario 20 introduced **no new external raw dataset**. Formal hunting reused **39 processed source files** from Scenarios 10, 11, 13, 15, 16, 17, 18, and 19.

The original analysis ledger recorded path, row count, size, SHA-256, and read status for those 39 inputs. A subsequent Git-history provenance review established:

- **15 / 39** recorded hashes match reachable committed Git blobs;
- **24 / 39** recorded hashes do **not** match any blob in reachable Git history.

The 24 unmatched records are retained exactly as historical SHA-256 provenance and marked `historical_hash_only_no_reachable_git_blob`. They are **not** represented as reproducible from a Git commit and are not rewritten to match later cleaned source files.

Coverage precision review also depends on **8 material rule/query/specification artifacts**. Those references are pinned to reviewed repository state `7f0f92b`.

The final provenance ledger is:

- `evidence/processed/source-sha256-records.tsv`

## Reproducibility interpretation

A `git_reproducible=true` hunt-input row can be reconstructed from its listed `source_commit` and `relative_path`.

A `git_reproducible=false` row preserves the original Scenario 20 source hash but has `source_commit=not_available`. This is an explicit evidence limitation: the historical blob may have existed only in a local working tree or in history no longer reachable from the repository.

This limitation affects **Git-level source reproducibility**, not the meaning of the already-published Scenario 20 processed findings. Those findings remain bounded to the processed evidence reviewed at analysis time.

## Licence handling

Scenario 20 does not re-license or redistribute another scenario's raw dataset. Dataset/source licensing remains inherited from the corresponding source scenario's source/licence documentation.

## Privacy and sanitisation

No raw cross-scenario evidence is copied into Scenario 20. Published `hunt-results.csv` contains the bounded processed fields needed to support the hunt findings; no duplicate sanitised-excerpt copy is maintained.
