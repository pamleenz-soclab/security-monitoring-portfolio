# Lessons Learned

1. **Coverage is semantic.** A rule file must be inspected for what it actually correlates before classifying a behaviour as uncovered.
2. **Partial detection matters.** Existing logic may cover a core sequence while a hunt adds context beyond the alert's terminal event.
3. **Logging gaps and detection gaps are different engineering problems.** Adding another rule cannot compensate for missing database audit or missing cross-host telemetry.
4. **Stable identifiers determine correlation quality.** Session IDs, Logon IDs, ProcessGuids, application/service-principal IDs, and token/request IDs enable stronger joins than names or time proximity alone.
5. **Negative hunts are useful evidence.** They document what the reviewed dataset did not show while preserving scope limitations.
6. **Hunting logic can be broader than alert logic.** Broad search is appropriate for exploration even when the same logic would be too noisy as an alert.
7. **Precision correction is part of quality assurance.** HC-07 was rerun after the first evaluator incorrectly interpreted a composite threshold field; the corrected result was retained with documented semantics.
8. **ATT&CK mapping is taxonomy, not measurement.** It supports behavioural description but does not produce a defensible coverage percentage by itself.
