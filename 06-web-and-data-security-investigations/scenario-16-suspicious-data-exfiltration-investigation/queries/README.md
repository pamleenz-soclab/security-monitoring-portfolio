# Query Notes

The queries are field-mapping examples, not drop-in production detections. Confirm product semantics before use, especially:

- request versus response byte direction
- NAT and proxy fields
- client identity behind recursive resolvers
- DNS query normalisation and trailing dots
- process/network join keys
- sampled or aggregated flow telemetry
- multi-value DNS fields

A query match is a detection opportunity, not proof of successful exfiltration. Receiver-side, application, DLP, or reconstruction evidence is required for a confirmed outcome.

## Scenario-specific interpretation

- `dns-tunnelling` is the primary behavioural analytic for the observed low-and-slow pattern.
- `burst-threshold` is a companion high-rate analytic and is **not expected to detect this exact dataset** at its current 5-minute threshold.
- `volume-anomaly` is supplemental and depends on correctly mapped client-to-resolver request bytes; bidirectional byte counters must not be substituted without validation.
- `file-activity-to-dns-transfer` is a production correlation example. The scenario itself did **not** show a central staging archive; file-event schemas must support the selected read/open/change actions before deployment.
- Process/network joins should use a process identifier when available. Same-host temporal proximity alone must be labelled as correlation, not direct attribution.
