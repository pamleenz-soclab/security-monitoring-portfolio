# Source and License Record

Scenario 19 reuses only processed/sanitised evidence and public detection artefacts from Scenarios 11, 12, 15, 16, 17 and 18. Raw or working evidence from those scenarios is not copied here.

`evidence/processed/source-sha256-records.tsv` records only source paths that exist at the referenced repository commit, together with their SHA-256 values and source commit. This avoids retaining invalid repository paths after earlier scenarios are cleaned up or renamed. The Scenario 19 source-derived fixtures retain minimum behavioural semantics rather than full source records.

Public test fixtures are newly created Scenario 19 artefacts. Sanitised-derived fixtures use aliases/documentation ranges and preserve only the timing and field relationships needed to test rule semantics.

Any third-party dataset licensing remains governed by the corresponding source scenario's source/license record. Scenario 19 does not republish raw third-party logs.
