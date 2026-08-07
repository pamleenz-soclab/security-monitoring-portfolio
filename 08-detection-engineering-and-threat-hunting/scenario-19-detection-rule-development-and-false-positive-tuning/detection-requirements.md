# Detection Requirements

Each formal rule must define: detects/does-not-detect scope, mandatory telemetry, strong telemetry, trigger unit, alert entity, window/threshold where applicable, deduplication, severity, confidence, response guidance, ATT&CK mapping boundary, test status, platform status and limitations.

The authoritative machine-readable requirements are `evidence/processed/rule-requirement-matrix.csv` and `detections/specifications/*.yml`.

Important final requirements include: R19-01 does not require SessionId; R19-03 counts distinct transactions; R19-04 requires both service-principal and credential stable IDs; R19-05 relies on governed group identity rather than display-name allowlists; and R19-06 deduplicates before counting unique chunks and never requires a completion marker.
