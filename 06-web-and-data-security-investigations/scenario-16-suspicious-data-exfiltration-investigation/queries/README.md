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
