# Cross-Platform Portability

Rule translation is not treated as semantic equivalence.

R19-03 and R19-04 provide the strongest cross-platform comparison. The v3 R19-04 implementations require both service-principal and credential stable IDs; earlier source implementations did not all enforce that invariant. R19-03 platform burst queries use fixed five-minute bins while the canonical evaluator uses a sliding five-minute window, so they are semantic approximations until native scheduling/bin-boundary behaviour is validated.

R19-02 and R19-06 Sigma files are primitives, not complete correlation rules. R19-01 Splunk is an approximation and needs native event-order validation. Native execution status for all platform files is `Not tested`.

See `evidence/processed/cross-platform-semantic-comparison.csv`.
