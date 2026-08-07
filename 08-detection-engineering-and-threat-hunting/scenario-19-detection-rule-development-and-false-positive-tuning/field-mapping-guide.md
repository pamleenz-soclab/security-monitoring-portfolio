# Field Mapping Guide

Cross-platform field mapping is classified as exact, approximate, derived, unavailable, or semantically incompatible. Similar field names are not assumed to represent the same entity.

Examples:

- Sysmon `ProcessGuid` is a stronger process-correlation key than a PID; ECS `process.entity_id` can be an approximation depending on ingestion.
- A WAF transaction ID is not equivalent to a Zeek `uid`, Suricata `flow_id`, or Entra request ID.
- Entra application object ID, app ID and service-principal object ID are distinct identities.
- Native source record IDs are preferred for exact deduplication; source/destination/query alone is not an adequate DNS duplicate key.

See `evidence/processed/source-field-mapping.csv`.
