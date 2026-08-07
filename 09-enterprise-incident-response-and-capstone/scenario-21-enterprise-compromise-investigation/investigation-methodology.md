# Investigation Methodology

The investigation followed this evidence-led process:

1. Establish dataset provenance and keep raw evidence read-only.
2. Normalize time while preserving source timestamps and uncertainty.
3. Select an actionable lead without consulting emulation ground truth.
4. Pivot first on stable identifiers: `ProcessGuid`, `ParentProcessGuid`, and `LogonId`.
5. Use account/host/IP/time relationships only where stable identifiers do not cross a boundary.
6. Separate direct observation, correlation, and inference.
7. Precisely validate high-risk candidates for false positives.
8. Build scope and impact only after correlation.
9. Design containment/recovery with business-risk and verification criteria.
10. Assess detection, logging, visibility, and investigation gaps separately.

## Correlation strength

**Strong:** exact stable identifiers or direct structural lineage.

**Moderate:** multiple matching entities plus a tight time relationship, where no stable identifier spans the telemetry boundary.

**Weak:** timing/pattern similarity alone. Weak links are not used to claim the final attack chain.

## Ground truth

ATT&CK/emulation plans are validation references only. The investigation findings were generated from telemetry first; the first-pass script likewise preserved candidate/provisional states rather than converting ATT&CK compatibility into final causal conclusions.
