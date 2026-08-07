# Canonical Event Schema

Scenario 19 uses a narrow canonical schema so rules can be reasoned about independently of vendor syntax. Canonical fields preserve semantic differences rather than forcing false equivalence.

`event_time` is the detection ordering timestamp. `ingestion_time` is intentionally separate. `application_id`, `application_object_id`, and `service_principal_id` are separate fields because they are not interchangeable. `session_id` is separate from request/correlation/token identifiers. `event_record_id` is preferred for deduplication where a source provides a stable record identity.

See `evidence/processed/canonical-event-schema.csv` for the complete field list.
